import "pe"
rule _ASProtect_v11_MTEb_
{
	meta:
		description = "ASProtect v1.1 MTEb"
	strings:
		$0 = {90 60 E8 1B E9}
	condition:
		$0 at pe.entry_point
}