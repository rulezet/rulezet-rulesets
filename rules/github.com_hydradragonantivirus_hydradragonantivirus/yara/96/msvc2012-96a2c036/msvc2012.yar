import "pe"
rule MSVC2012
{
	meta:
		author="_pusher_"
		date = "2016-08"
		linker = "11.00"
	condition:
		pe.rich_signature.version(65501) and pe.rich_signature.version(65500) and pe.rich_signature.toolid(211) or
		pe.rich_signature.version(50929) and pe.rich_signature.version(61030) and pe.rich_signature.toolid(206) or
		(pe.rich_signature.version(50929) or pe.rich_signature.version(65501)) and (pe.linker_version.major == 11) and (pe.linker_version.minor == 0 )
}