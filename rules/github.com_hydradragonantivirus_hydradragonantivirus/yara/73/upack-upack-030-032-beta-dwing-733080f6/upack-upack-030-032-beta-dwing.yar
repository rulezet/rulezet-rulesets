import "pe"
rule _Upack_Upack_030__032_beta__Dwing_
{
	meta:
		description = "Upack Upack 0.30 - 0.32 beta -> Dwing"
	strings:
		$0 = {8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 1C 2B C7 AB E2 E5 8B 5E 34 8B 76 38 46 AD ?? C0 0F 84}
	condition:
		$0 at pe.entry_point
}