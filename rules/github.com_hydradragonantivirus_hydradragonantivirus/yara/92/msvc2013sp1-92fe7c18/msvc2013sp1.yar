import "pe"
rule MSVC2013sp1
{
	meta:
		author = "_pusher_"
		date = "2016-08"
		linker = "12.10"
	condition:
		pe.rich_signature.version(30102) and pe.rich_signature.version(30102) and pe.rich_signature.toolid(242) or
		pe.rich_signature.version(40116) and pe.rich_signature.toolid(240) and pe.rich_signature.toolid(237)
		
}