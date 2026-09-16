rule Win_Trojan_800_1
{
strings:
	$a0 = { b9810151ad33d0e2fb5931154747e2fa }


condition:
	$a0
}