rule Win_Trojan_Beethoven_2
{
strings:
	$a0 = { 5bb96e0683eb03b41580eca44b2e3027e2f7e99af9 }


condition:
	$a0
}