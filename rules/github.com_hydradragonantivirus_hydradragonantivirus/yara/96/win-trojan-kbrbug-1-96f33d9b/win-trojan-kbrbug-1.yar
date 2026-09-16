rule Win_Trojan_KbrBug_1
{
strings:
	$a0 = { 2effb5ff06bbea05b91401582e300143e2fa5b1fe8d1fe }


condition:
	$a0
}