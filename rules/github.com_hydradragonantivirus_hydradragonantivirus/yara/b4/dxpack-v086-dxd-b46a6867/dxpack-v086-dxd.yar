import "pe"
rule _DxPack_V086_Dxd_
{
	meta:
		description = "DxPack V0.86 ->Dxd"
	strings:
		$0 = {60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00}
	condition:
		$0 at pe.entry_point
}