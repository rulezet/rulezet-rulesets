import "pe"
rule _PE_Packer__Vecna_
{
	meta:
		description = "PE Packer -> Vecna"
	strings:
		$0 = {FC 8B 35 70 01 40 00 83 EE 40 6A 40 68 00 30 10}
	condition:
		$0 at pe.entry_point
}