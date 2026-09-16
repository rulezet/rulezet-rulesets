import "pe"
rule _Krypton_v05_
{
	meta:
		description = "Krypton v0.5"
	strings:
		$0 = {E8 5D 81 ED 64 A1 30 84 C0 74 64 A1 20 0B C0}
	condition:
		$0 at pe.entry_point
}