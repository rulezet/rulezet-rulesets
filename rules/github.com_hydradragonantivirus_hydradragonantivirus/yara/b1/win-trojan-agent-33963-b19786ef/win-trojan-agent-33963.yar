rule Win_Trojan_Agent_33963
{
strings:
	$a0 = { 609c6828555c00e874000000eb01c2eb }


condition:
	$a0
}