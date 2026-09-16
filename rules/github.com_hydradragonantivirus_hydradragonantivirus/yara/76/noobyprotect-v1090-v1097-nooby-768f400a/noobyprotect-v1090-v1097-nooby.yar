import "pe"
rule _NoobyProtect_V1090__V1097__Nooby_
{
	meta:
		description = "NoobyProtect V1.0.9.0 - V1.0.9.7 -> Nooby"
	strings:
		$0 = {53 51 E8 00 00 00 00 8B 1C 24 83 C3 25 33 C9 87 4B FC 83 F9 00 74 06 80 33 ?? 43 E2 FA 83 C4 04 59 5B 9D E9 04 00 00 00}
	condition:
		$0 at pe.entry_point
}