import "pe"
rule _Armadillo_v220_
{
	meta:
		description = "Armadillo v2.20"
	strings:
		$0 = {55 8B EC 6A FF 68 10 12 41 00 68 F4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at pe.entry_point
}