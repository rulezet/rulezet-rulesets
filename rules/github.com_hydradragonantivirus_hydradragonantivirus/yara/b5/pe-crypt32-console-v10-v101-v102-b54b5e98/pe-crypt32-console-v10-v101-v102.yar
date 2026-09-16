import "pe"
rule _PE_Crypt32_Console_v10_v101_v102_
{
	meta:
		description = "PE Crypt32 (Console v1.0, v1.01, v1.02)"
	strings:
		$0 = {8B 04 24 9C 60 E8 5D 81 ED 0A 45 40 80 BD 67 44 40 0F 85}
	condition:
		$0 at pe.entry_point
}