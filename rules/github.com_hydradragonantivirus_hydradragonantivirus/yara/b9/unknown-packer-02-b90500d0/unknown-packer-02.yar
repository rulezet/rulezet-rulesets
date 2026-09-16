import "pe"
rule _Unknown_packer_02_
{
	meta:
		description = "Unknown packer (02)"
	strings:
		$0 = {FA 8C DE 8C CF 8E DF 8E C7 83 C7 ?? BB}
	condition:
		$0 at pe.entry_point
}