import "pe"
rule _PE_Diminisher_01__Teraphy__Phrozen_Crew_
{
	meta:
		description = "PE Diminisher 0.1 -> Teraphy / Phrozen Crew"
	strings:
		$0 = {53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00}
	condition:
		$0 at pe.entry_point
}