import "pe"
rule _Krypton_v04_
{
	meta:
		description = "Krypton v0.4"
	strings:
		$0 = {54 E8 5D 8B C5 81 ED 71 44 2B 85 64 60 EB 43}
	condition:
		$0 at pe.entry_point
}