import "pe"
rule _Unknown_virus_1_
{
	meta:
		description = "Unknown virus 1"
	strings:
		$0 = {E9 01 00 1A EB 4E C3 00 00 00 95 E3 AC B1 07 01 01 00 17 05 60 08 01 00 CE 10 20 00 CE 10 0A 04 00 00 FB 04 F8 4F D2 19 72 D3 32 33 AC 1F 73 EA A1 DB C9 38 AD 69 AD 9E 1E 00 20 00 08 00 B4 40 BB 02 00 8B 4C 0A 8B 54 08 03 D6 CD 21 B8 FF 4C}
	condition:
		$0 at pe.entry_point
}