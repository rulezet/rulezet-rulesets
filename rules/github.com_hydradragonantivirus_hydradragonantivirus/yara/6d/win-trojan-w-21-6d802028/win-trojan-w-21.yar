rule Win_Trojan_W_21
{
strings:
	$a0 = { b90d00f3a4061fba1200e8a8040bc07503e993008bd8ba3500b94000e8a204813e35004d5a }


condition:
	$a0
}