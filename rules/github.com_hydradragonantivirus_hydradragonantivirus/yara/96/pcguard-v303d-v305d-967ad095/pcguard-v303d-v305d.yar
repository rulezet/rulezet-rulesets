import "pe"
rule _PCGuard_v303d_v305d_
{
	meta:
		description = "PC-Guard v3.03d, v3.05d"
	strings:
		$0 = {FC 55 50 E8 ?? ?? ?? ?? 5D EB}
	condition:
		$0 at pe.entry_point
}