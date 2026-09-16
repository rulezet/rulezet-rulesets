rule Win_Trojan_JD_2
{
strings:
	$a0 = { 055600a39e01ba0001b19eb440cd2133 }


condition:
	$a0
}