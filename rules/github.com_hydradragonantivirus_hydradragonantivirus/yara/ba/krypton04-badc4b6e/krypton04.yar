import "pe"
rule krypton04
{
	meta:
		author = "PEiD"
		description = "Krypton 0.4 -> Yado/Lockless"
		group = "129"
		function = "0"
	strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06 }
	condition:
		$a0 at pe.entry_point
}