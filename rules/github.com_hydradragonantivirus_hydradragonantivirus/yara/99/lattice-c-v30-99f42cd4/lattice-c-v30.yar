import "pe"
rule _Lattice_C_v30_
{
	meta:
		description = "Lattice C v3.0"
	strings:
		$0 = {FA B8 ?? ?? 8E D8 B8 ?? ?? 8E}
	condition:
		$0 at pe.entry_point
}