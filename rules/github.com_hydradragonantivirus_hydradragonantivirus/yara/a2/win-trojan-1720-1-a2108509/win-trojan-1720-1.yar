rule Win_Trojan_1720_1
{
strings:
	$a0 = { 5b81c31000b99f0633f680305c46e2fa }


condition:
	$a0
}