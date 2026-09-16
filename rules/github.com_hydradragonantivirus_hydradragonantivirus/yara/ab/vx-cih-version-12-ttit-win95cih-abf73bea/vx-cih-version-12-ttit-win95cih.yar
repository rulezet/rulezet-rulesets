import "pe"
rule _Vx_CIH_Version_12_TTIT__WIN95CIH__
{
	meta:
		description = "Vx: CIH Version 1.2 TTIT (! WIN95CIH !)"
	strings:
		$0 = {55 8D ?? ?? ?? 33 DB 64 87 03 E8 ?? ?? ?? ?? 5B 8D}
	condition:
		$0 at pe.entry_point
}