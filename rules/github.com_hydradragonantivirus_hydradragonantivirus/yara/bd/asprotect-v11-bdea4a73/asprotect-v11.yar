import "pe"
rule _ASProtect_v11_
{
	meta:
		description = "ASProtect v1.1"
	strings:
		$0 = {60 E9 91 78 79 79 79}
	condition:
		$0 at pe.entry_point
}