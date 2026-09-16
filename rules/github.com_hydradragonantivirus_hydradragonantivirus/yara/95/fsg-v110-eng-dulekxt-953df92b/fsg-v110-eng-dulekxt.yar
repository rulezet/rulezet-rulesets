import "pe"
rule _FSG_v110_Eng__dulekxt_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt"
	strings:
		$0 = {BB D0 01 40 ?? BF ?? 10 40 ?? BE}
		$1 = {E8 01 00 00 00 ?? ?? E8 ?? 00 00 00}
		$2 = {EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}