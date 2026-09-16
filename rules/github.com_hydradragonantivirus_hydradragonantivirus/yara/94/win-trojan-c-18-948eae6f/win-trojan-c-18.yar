rule Win_Trojan_C_18
{
strings:
	$a0 = { b440b92f018d960401cd21e80100c33e8b860c018db63e01b97b0031044646e2fac3 }


condition:
	$a0
}