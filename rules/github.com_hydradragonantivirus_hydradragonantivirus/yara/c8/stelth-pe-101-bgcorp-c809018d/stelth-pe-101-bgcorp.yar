import "pe"
rule _Stelth_PE_101__BGCorp_
{
	meta:
		description = "Ste@lth PE 1.01 -> BGCorp"
	strings:
		$0 = {BA ?? ?? ?? 00}
	condition:
		$0 at pe.entry_point
}