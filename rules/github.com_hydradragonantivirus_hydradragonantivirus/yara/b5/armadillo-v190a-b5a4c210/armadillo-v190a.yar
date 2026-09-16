import "pe"
rule _Armadillo_v190a_
{
	meta:
		description = "Armadillo v1.90a"
	strings:
		$0 = {55 8B EC 64 FF 68 10 F2 40 00 68 14 9B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at pe.entry_point
}