rule Win_Trojan_Betaboys_1
{
strings:
	$a0 = { 03018d9e20018d968b013e8a8e03013bda7405300f43ebf790 }


condition:
	$a0
}