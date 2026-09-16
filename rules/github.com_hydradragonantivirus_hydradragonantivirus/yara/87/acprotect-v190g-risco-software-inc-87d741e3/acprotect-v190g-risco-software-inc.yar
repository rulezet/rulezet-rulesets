import "pe"
rule _ACProtect_v190g__Risco_software_Inc_
{
	meta:
		description = "ACProtect v1.90g -> Risco software Inc."
	strings:
		$0 = {60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3}
	condition:
		$0 at pe.entry_point
}