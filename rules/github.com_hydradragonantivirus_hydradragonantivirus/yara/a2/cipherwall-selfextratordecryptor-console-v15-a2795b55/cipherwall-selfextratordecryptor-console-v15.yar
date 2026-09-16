import "pe"
rule _CipherWall_SelfExtratorDecryptor_Console_v15_
{
	meta:
		description = "CipherWall Self-Extrator/Decryptor (Console) v1.5"
	strings:
		$0 = {60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D}
	condition:
		$0 at pe.entry_point
}