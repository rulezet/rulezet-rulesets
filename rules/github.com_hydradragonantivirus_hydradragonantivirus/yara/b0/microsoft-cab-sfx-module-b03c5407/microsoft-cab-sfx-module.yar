import "pe"
rule _Microsoft_CAB_SFX_module_
{
	meta:
		description = "Microsoft CAB SFX module"
	strings:
		$0 = {55 8B EC 83 EC 44 56 FF 15 94 13 42 ?? 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E}
	condition:
		$0 at pe.entry_point
}