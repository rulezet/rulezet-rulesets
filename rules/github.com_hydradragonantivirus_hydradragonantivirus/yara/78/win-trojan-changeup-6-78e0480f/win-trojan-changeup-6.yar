rule Win_Trojan_Changeup_6
{
strings:
	$a0 = { 43686565746100[9]0000 }


condition:
	$a0
}