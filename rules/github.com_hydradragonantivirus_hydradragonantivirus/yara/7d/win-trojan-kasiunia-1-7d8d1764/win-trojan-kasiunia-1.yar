rule Win_Trojan_Kasiunia_1
{
strings:
	$a0 = { bb1400baad0e2e3007434a[0-4]75f5 }


condition:
	$a0
}