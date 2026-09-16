import "pe"
rule _Nullsoft_Install_System_v198___Nullsoft_
{
	meta:
		description = "Nullsoft Install System v1.98 ->  Nullsoft"
	strings:
		$0 = {83 EC 0C 53 56 57 FF 15 2C 81 40}
	condition:
		$0 at pe.entry_point
}