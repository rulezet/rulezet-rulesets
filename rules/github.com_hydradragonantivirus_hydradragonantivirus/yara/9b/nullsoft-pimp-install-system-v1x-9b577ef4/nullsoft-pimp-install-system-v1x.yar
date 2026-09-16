import "pe"
rule _Nullsoft_PIMP_Install_System_v1x_
{
	meta:
		description = "Nullsoft PIMP Install System v1.x"
	strings:
		$0 = {FF 60 FF CA FF ?? BA DC 0D E0 40 ?? 50 ?? 60 ?? 70 ??}
	condition:
		$0 at pe.entry_point
}