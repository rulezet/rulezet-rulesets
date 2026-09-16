import "pe"
rule splasher1_3
{
	meta:
		author = "PEiD"
		description = "Splasher 1.0 - 3.0 -> Tola/Amok"
		group = "175"
		function = "0"
	strings:
		$a0 = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84 }
	condition:
		$a0 at pe.entry_point
}