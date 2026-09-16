rule Win_Trojan_Boot_5
{
strings:
	$a0 = { ad920a165c008d32b80103565152cd13 }


condition:
	$a0
}