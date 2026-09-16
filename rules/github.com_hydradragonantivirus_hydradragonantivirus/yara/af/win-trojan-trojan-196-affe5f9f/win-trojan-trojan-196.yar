rule Win_Trojan_Trojan_196
{
strings:
	$a0 = { e800005b81c31000b99f0633f680307e46e2fa }


condition:
	$a0
}