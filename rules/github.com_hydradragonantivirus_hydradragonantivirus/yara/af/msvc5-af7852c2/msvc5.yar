import "pe"
rule MSVC5
{
	meta:
		author="_pusher_"
		date = "2016-08"
		linker = "5.10"
			condition:
		pe.rich_signature.version(1668) and pe.rich_signature.toolid(6)
}