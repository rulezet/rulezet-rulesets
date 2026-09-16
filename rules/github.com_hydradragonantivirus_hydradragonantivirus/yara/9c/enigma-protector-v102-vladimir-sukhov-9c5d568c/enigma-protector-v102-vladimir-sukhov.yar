import "pe"
rule _Enigma_protector_v102__Vladimir_Sukhov_
{
	meta:
		description = "Enigma protector v1.02 -> Vladimir Sukhov"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB 01 83 64 89 20 EB 02 CD 20 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 90 58 61 EB 01 3E BE 01 00 00 00 C1 E6 02 83 EC 04 87 DE 89 1C 24}
		$1 = {55 53 20 50 54 4F 20 00}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}