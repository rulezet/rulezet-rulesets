rule Win_Trojan_Trojan_317
{
strings:
	$a0 = { b92601813446124646e2f8c3 }


condition:
	$a0
}