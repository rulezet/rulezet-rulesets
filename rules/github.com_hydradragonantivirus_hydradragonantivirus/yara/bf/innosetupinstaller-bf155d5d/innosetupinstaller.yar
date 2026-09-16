import "pe"
rule InnoSetupInstaller : Jordan Russel
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 72 44 6C 50 74 53 }
		$a1 = { 49 6E 6E 6F 20 53 65 74 75 70 20 53 65 74 75 70 20 44 61 74 61 }
		$a2 = { 7A 6C 62 }

	condition:
		$a0 and $a1 and
		$a2 at (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)
}