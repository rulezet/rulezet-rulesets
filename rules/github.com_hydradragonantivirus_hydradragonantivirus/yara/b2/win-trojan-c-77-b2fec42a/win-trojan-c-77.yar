rule Win_Trojan_C_77
{
strings:
	$a0 = { e78deb2ab81e1c87e9e82afecc7516b1ff3f1c03007c0f7f08813e1a032c1976054e87e3eb }


condition:
	$a0
}