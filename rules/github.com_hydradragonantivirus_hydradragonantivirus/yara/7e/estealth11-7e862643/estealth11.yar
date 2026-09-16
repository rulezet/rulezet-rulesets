import "pe"
rule estealth11
{
	meta:
		author = "PEiD"
		description = "EXEStealth 1.1 (y0da's Cryptor Clone) -> WebtoolMaster"
		group = "119"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED FB 1D 40 ?? B9 7B 09 00 00 8B F7 AC }
	condition:
		$a0 at pe.entry_point
}