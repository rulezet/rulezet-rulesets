import "pe"
rule _Unknown_packer_06_
{
	meta:
		description = "Unknown packer (06)"
	strings:
		$0 = {FA B8 ?? ?? BE ?? ?? 33 F0 0E 17 2E ?? ?? ?? BA ?? ?? 87 E6 5B 33 DC}
	condition:
		$0 at pe.entry_point
}