import "pe"
rule _Unknown_packer_04_
{
	meta:
		description = "Unknown packer (04)"
	strings:
		$0 = {BC ?? ?? C3 2E FF 2E ?? ?? CF}
	condition:
		$0 at pe.entry_point
}