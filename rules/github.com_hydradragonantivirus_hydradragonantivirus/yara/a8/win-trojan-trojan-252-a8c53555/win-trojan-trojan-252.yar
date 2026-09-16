rule Win_Trojan_Trojan_252
{
strings:
	$a0 = { b99f02482e300446e2f9c3 }


condition:
	$a0
}