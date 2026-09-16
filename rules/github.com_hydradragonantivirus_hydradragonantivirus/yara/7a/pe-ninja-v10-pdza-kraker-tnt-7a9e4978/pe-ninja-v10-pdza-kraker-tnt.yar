import "pe"
rule _PE_Ninja_v10__pDzA_kRAker_TNT_
{
	meta:
		description = "PE Ninja v1.0 -> +DzA kRAker TNT"
	strings:
		$0 = {BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at pe.entry_point
}