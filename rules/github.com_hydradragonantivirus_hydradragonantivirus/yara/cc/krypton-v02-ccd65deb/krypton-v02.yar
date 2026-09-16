import "pe"
rule _Krypton_v02_
{
	meta:
		description = "Krypton v0.2"
	strings:
		$0 = {8B 0C 24 E9 C0 8D 01 C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71}
	condition:
		$0 at pe.entry_point
}