rule Win_Trojan_Sality_1014
{
strings:
	$a0 = { 60e85200000066b9002868????????8dbd00104000033c248bf7 }


condition:
	$a0
}