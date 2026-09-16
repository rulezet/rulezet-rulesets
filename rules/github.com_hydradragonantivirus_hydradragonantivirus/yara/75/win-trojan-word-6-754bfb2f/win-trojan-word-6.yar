rule Win_Trojan_Word_6
{
strings:
	$a0 = { 21bbf4048037e44381fb570a72 }


condition:
	$a0
}