import "pe"
rule _Nullsoft_PiMP_Install_System_
{
	meta:
		description = "Nullsoft PiMP Install System"
	strings:
		$0 = {83 EC ?? 53 55 56}
	condition:
		$0 at pe.entry_point
}