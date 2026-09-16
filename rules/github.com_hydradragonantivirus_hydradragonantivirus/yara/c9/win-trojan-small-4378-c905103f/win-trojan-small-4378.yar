rule Win_Trojan_Small_4378
{
strings:
	$a0 = { b810008010c1c03250 }


condition:
	$a0
}