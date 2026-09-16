rule Win_Trojan_Tiny_49
{
strings:
	$a0 = { 84ab01b4408d940501b9a300cd217215 }


condition:
	$a0
}