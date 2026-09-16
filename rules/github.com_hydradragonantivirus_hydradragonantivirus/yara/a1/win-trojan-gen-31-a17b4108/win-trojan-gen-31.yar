rule Win_Trojan_Gen_31
{
strings:
	$a0 = { 018a540588160001b42acd21f6c20175 }


condition:
	$a0
}