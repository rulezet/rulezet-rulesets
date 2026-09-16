import "pe"
rule _ASProtect_v11_BRS_
{
	meta:
		description = "ASProtect v1.1 BRS"
	strings:
		$0 = {68 01}
	condition:
		$0 at pe.entry_point
}