rule Win_Trojan_Small_4386
{
strings:
	$a0 = { b81000801dc1c03250 }


condition:
	$a0
}