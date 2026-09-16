rule Win_Trojan_KbrBug_3
{
strings:
	$a0 = { 5d04bbde03b97f00582e300143e2fa5be85fff }


condition:
	$a0
}