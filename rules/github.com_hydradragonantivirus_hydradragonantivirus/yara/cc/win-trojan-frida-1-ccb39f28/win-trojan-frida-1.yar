rule Win_Trojan_Frida_1
{
strings:
	$a0 = { 0153c6078083c306b907027f070043e2fa }


condition:
	$a0
}