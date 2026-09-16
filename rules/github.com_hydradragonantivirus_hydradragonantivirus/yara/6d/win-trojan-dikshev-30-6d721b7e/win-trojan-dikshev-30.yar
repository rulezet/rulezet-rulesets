rule Win_Trojan_Dikshev_30
{
strings:
	$a0 = { b44e87cecd217301c3be9e00bf380157acaa3c2e75fabe3401a5a55ab45bcd21720893b440ba380087d1ebd8 }


condition:
	$a0
}