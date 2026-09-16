rule Win_Trojan_MemoryLapse_2
{
strings:
	$a0 = { cc93b8024233c999cc2d030089864802b4408d9603 }


condition:
	$a0
}