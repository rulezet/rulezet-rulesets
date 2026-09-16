rule Win_Trojan_C_17
{
strings:
	$a0 = { b440b921018d960401cd21e80100c33e8b860c018db63901b9760031044646e2fac3 }


condition:
	$a0
}