import "pe"
rule _PCGuard_v405d_v410d_v415d_
{
	meta:
		description = "PC-Guard v4.05d, v4.10d, v4.15d"
	strings:
		$0 = {FC 55 50 E8 ?? ?? ?? ?? 5D 60 E8 03 ?? ?? ?? 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 30 D2 40 ?? EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B}
	condition:
		$0 at pe.entry_point
}