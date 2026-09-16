import "pe"
rule _PEncrypt_v31_
{
	meta:
		description = "PEncrypt v3.1"
	strings:
		$0 = {B8 93 ?? 55 50 67 64 FF 36 ?? ?? 67 64 89 26 ?? ?? BD 4B 48 43 42 B8 04 ?? ?? ?? CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 ?? ?? 58 5D BB ?? ?? 40 ?? 33 C9 33}
	condition:
		$0 at pe.entry_point
}