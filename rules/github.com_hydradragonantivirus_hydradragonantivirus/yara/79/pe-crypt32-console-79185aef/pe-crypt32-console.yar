import "pe"
rule _PE_Crypt32_Console_
{
	meta:
		description = "PE Crypt32 [Console"
	strings:
		$0 = {E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB}
	condition:
		$0 at pe.entry_point
}