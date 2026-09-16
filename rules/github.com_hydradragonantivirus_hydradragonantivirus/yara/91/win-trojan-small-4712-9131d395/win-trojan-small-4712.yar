rule Win_Trojan_Small_4712
{
strings:
	$a0 = { 6d652e62697a2f73797374656d2f6f6b2e7068703f6163633d313131 }


condition:
	$a0
}