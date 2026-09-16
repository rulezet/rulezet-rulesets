import "pe"
rule _GCCCYGWINMSYS_sign_ASL_
{
	meta:
		description = "GCC-CYGWIN-MSYS_sign_ASL"
	strings:
		$0 = {55 89 E5 83 EC 08 A1 00 ?? ?? 00 85 C0 74 01 CC D9 7D FE 0F B7 4D FE 81 E1 C0 F0 FF FF 66 89 4D FE 0F B7 55 FE 81 CA 3F 03 00 00 66 89 55 FE D9 6D FE}
	condition:
		$0 at pe.entry_point
}