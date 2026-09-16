import "pe"
rule yc1
{
	meta:
		author = "PEiD"
		description = "yoda's cryptor 1.0"
		group = "195"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED E7 1A 40 ?? E8 A1 ?? ?? ?? E8 D1 ?? ?? ?? E8 85 01 ?? ?? F7 85 }
	condition:
		$a0 at pe.entry_point
}