rule Win_Trojan_Hzp_1
{
strings:
	$a0 = { bf1c00b9ec01068ccb8edb8035bb47e2fae80000 }


condition:
	$a0
}