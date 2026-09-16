import "pe"
rule MSVC2010
{
	meta:
		author="_pusher_"
		date = "2016-08"
		linker = "10.00"
	condition:
		pe.rich_signature.version(40219) and 
				 
		( pe.rich_signature.version(30729) or pe.rich_signature.version(40310) or pe.rich_signature.version(4035) ) and 
		(pe.rich_signature.toolid(171) or pe.rich_signature.toolid(174) or pe.rich_signature.toolid(175) or pe.rich_signature.toolid(170)  )  or

		pe.rich_signature.version(20804) and pe.rich_signature.version(50727) and pe.rich_signature.toolid(170) or
		pe.rich_signature.version(30319) and (pe.linker_version.major == 10) and (pe.linker_version.minor == 0 )
}