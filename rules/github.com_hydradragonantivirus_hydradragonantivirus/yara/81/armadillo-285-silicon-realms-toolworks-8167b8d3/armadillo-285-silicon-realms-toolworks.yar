import "pe"
rule _Armadillo_285__Silicon_Realms_Toolworks_
{
	meta:
		description = "Armadillo 2.85 -> Silicon Realms Toolworks"
	strings:
		$0 = {55 8B EC 6A FF 68 68 ?? ?? 00 68 00 ?? ?? 00 64 A1 00 00 00 00 50 64 89 25}
	condition:
		$0 at pe.entry_point
}