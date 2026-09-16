import "pe"
rule _PE_Intro_v10__Predator_NLS_
{
	meta:
		description = "PE Intro v1.0 -> Predator NLS"
	strings:
		$0 = {8B 04 24 9C 60 E8 00 00 00 00 5D 81 ED 0A 45 40 00 80 BD 67 44 40 00 00 0F 85 48}
	condition:
		$0 at pe.entry_point
}