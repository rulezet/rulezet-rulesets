import "pe"
rule _Unknown_packer_03_
{
	meta:
		description = "Unknown packer (03)"
	strings:
		$0 = {06 1E 57 56 50 53 51 52 BD ?? ?? 0E 1F 8C}
	condition:
		$0 at pe.entry_point
}