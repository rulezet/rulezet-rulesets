import "pe"
rule _Enigma_Protector_V11XV15X__Sukhov_Vladimir__Serge_N_Markin_
{
	meta:
		description = "Enigma Protector V1.1X-V1.5X -> Sukhov Vladimir & Serge N. Markin"
	strings:
		$0 = {55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9}
	condition:
		$0 at pe.entry_point
}