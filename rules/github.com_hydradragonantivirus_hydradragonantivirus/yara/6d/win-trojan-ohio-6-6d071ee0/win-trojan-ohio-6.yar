rule Win_Trojan_Ohio_6
{
strings:
	$a0 = { fafa8cc88ed88ed0bc00f0fbe8450073 }


condition:
	$a0
}