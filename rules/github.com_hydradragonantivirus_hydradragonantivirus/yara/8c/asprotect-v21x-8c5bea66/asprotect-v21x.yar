import "pe"
rule _ASProtect_v21x_
{
	meta:
		description = "ASProtect v2.1x"
	strings:
		$0 = {BB E9 60 9C FC BF B9 F3 AA 9D 61 C3 55 8B}
	condition:
		$0 at pe.entry_point
}