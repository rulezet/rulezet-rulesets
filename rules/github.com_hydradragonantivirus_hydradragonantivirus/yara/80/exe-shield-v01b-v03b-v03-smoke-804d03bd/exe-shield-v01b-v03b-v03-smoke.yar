import "pe"
rule _EXE_Shield_v01b__v03b_v03__SMoKE_
{
	meta:
		description = "EXE Shield v0.1b - v0.3b, v0.3 -> SMoKE"
	strings:
		$0 = {E8 04 00 00 00 83 60 EB 0C 5D EB 05}
	condition:
		$0 at pe.entry_point
}