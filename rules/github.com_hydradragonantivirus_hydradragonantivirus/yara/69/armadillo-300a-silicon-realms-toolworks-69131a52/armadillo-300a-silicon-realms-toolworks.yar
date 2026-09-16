import "pe"
rule _Armadillo_300a__Silicon_Realms_Toolworks_
{
	meta:
		description = "Armadillo 3.00a -> Silicon Realms Toolworks"
	strings:
		$0 = {60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F}
	condition:
		$0 at pe.entry_point
}