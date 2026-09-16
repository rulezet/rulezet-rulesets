rule _Private_exe_Protector_V20__SetiSoft_Team_
{
	meta:
		description = "Private exe Protector V2.0 -> SetiSoft Team"
	strings:
		$0 = {00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00}
	condition:
		$0
}