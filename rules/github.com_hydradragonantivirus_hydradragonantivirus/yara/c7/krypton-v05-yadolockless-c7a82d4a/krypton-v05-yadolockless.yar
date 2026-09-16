import "pe"
rule _Krypton_v05__yadolockless_
{
	meta:
		description = "Krypton v0.5 -> yado/lockless"
	strings:
		$0 = {54 E8 00 00 00 00 5D 8B C5 81 ED 71 44 ?? 00 2B 85 64 60 ?? 00 EB 43 DF}
	condition:
		$0 at pe.entry_point
}