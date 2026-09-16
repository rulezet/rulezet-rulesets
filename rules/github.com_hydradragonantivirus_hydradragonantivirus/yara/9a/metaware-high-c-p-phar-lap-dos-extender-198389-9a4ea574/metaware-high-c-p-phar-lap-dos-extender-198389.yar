import "pe"
rule _MetaWare_High_C_p_Phar_Lap_DOS_Extender_198389_
{
	meta:
		description = "MetaWare High C + Phar Lap DOS Extender 1983-89"
	strings:
		$0 = {B8 ?? ?? 8E D8 B8 ?? ?? CD 21 A3 ?? ?? 3C 03 7D ?? B4 09}
	condition:
		$0 at pe.entry_point
}