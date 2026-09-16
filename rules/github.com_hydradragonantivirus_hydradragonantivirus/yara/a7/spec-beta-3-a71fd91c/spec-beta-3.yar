import "pe"
rule _SPEC_beta_3_
{
	meta:
		description = "SPEC beta 3"
	strings:
		$0 = {5B 53 50 45 43 5D E8 00 00 00 00 5D 8B C5 81 ED 41 24 40 00 2B 85 89 26 40 00 83 E8 0B 89 85 8D 26 40 00 0F B6 B5 91 26 40 00 8B FD 8B 9D 8D 26 40 00 8B 87 96 26 40 00 03 D8 8B 8F 9A 26 40 00 8A 85 7C 26 40 00 00 03 FE C0 43 E2 F9 83 C7 08}
	condition:
		$0 at pe.entry_point
}