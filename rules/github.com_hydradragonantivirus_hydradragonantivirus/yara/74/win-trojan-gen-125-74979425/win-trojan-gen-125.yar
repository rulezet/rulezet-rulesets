rule Win_Trojan_Gen_125
{
strings:
	$a0 = { 51ad33d0e2fb5931154747e2fa }


condition:
	$a0
}