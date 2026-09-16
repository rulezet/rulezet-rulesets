import "pe"
rule pcg5
{
	meta:
		author = "PEiD"
		description = "PC-Guard 5.0 -> Blagoje Ceklic"
		group = "135"
		function = "0"
	strings:
		$a0 = { FC 55 50 E8 ?? ?? ?? ?? 5D 60 E8 03 ?? ?? ?? ?? ?? ?? EB 01 ?? 58 EB 01 ?? 40 EB 01 ?? FF E0 0B 61 B8 }
	condition:
		$a0 at pe.entry_point
}