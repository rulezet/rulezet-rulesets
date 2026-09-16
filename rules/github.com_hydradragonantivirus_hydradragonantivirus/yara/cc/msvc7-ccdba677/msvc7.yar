import "pe"
rule MSVC7
{
	meta:
		author="_pusher_"
		date = "2016-08"
		linker = "7.00"
	condition:
		pe.rich_signature.version(9210) and (pe.rich_signature.version(9178) or pe.rich_signature.version(9466)) and pe.rich_signature.toolid(29) or 		pe.rich_signature.version(8078) and pe.rich_signature.version(9210) and pe.rich_signature.toolid(19)
}