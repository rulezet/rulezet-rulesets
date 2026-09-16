import "pe"
rule _EXE_Shield_V01bV03b__SMoKE_
{
	meta:
		description = "EXE Shield V0.1b-V0.3b -> SMoKE"
	strings:
		$0 = {E8 04 00 00 00 83 60 EB 0C 5D EB 05}
	condition:
		$0 at pe.entry_point
}