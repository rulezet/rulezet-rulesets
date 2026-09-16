import "pe"
rule _Unknown_packer_01_
{
	meta:
		description = "Unknown packer (01)"
	strings:
		$0 = {EB ?? ?? BE ?? ?? BF ?? ?? 2E}
	condition:
		$0 at pe.entry_point
}