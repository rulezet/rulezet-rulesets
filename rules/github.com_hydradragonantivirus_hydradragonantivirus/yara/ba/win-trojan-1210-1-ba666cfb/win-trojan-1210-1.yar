rule Win_Trojan_1210_1
{
strings:
	$a0 = { 0175d00e0e1f07bed3042bc92e8a0446410ac0 }


condition:
	$a0
}