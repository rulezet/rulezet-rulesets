rule Win_Trojan_Accept_2
{
strings:
	$a0 = { 87db5b81eb03010e1f8a87230133ff87c9b9960e903081270187d247e2f7eb04 }


condition:
	$a0
}