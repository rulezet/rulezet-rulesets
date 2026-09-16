rule Win_Trojan_ExeHd_1
{
strings:
	$a0 = { 1501f3a4b81325061fba8301cd21b44a0e07bb3900cd210e1f8b1e2c008ec333c0bf01004faf75 }


condition:
	$a0
}