rule Win_Trojan_Accept_1
{
strings:
	$a0 = { e8000087db5b81eb03010e1f8a87230133ff87c9b9fc0d903081270187d247e2f7eb04 }


condition:
	$a0
}