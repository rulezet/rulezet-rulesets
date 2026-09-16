import "pe"
rule _Unknown_UPX_modifyer_
{
	meta:
		description = "Unknown UPX modifyer"
	strings:
		$0 = {E8 02 00 00 00 CD 03 5A 81 C2 ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 89 D1 81 C1 3C 05 00 00 52 81 2A 33 53 45 12 83 C2 04 39 CA 7E F3 89 CA 8B 42 04 8D 18 29 02 BB 78 56 00 00 83 EA 04 3B 14 24 7D EC C3}
	condition:
		$0 at pe.entry_point
}