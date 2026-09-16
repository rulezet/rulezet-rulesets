rule Win_Trojan_Cosenza_2
{
strings:
	$a0 = { 337587ed76f9d4fe2c008ac48bd8be2401b9300cb64e2e283446e2fa }


condition:
	$a0
}