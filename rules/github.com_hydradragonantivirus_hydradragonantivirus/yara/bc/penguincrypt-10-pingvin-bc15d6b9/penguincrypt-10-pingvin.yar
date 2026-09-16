import "pe"
rule _PEnguinCrypt_10__Pingvin_
{
	meta:
		description = "PEnguinCrypt 1.0 -> Pingvin"
	strings:
		$0 = {B8 93 ?? ?? 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0 32 0C 03 40 81 F8 00 01 00 00 75 F4 BB 75 ?? ?? 00 33 C0 32 0C 03 40 81 F8 36 01 00 00 75 F4 A1 35 ?? ?? 00 8B D9 68 75 ?? ?? 00 6A 40}
	condition:
		$0 at pe.entry_point
}