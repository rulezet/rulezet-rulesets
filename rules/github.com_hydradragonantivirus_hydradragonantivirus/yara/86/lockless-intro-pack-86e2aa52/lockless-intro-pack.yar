import "pe"
rule _Lockless_Intro_Pack_
{
	meta:
		description = "Lockless Intro Pack"
	strings:
		$0 = {55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 68 C0 69 44 ?? E8 E4 80 FF FF 59 E8 4E 29 ?? ?? E8 C9 0D ?? ?? 85 C0 75 08 6A FF E8 6E}
	condition:
		$0 at pe.entry_point
}