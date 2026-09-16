rule Win_Trojan_Monster_55
{
strings:
	$a0 = { b92c02be????8034??46e2fa }


condition:
	$a0
}