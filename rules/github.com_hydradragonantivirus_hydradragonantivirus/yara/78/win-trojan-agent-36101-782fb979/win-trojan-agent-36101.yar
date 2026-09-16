rule Win_Trojan_Agent_36101
{
strings:
	$a0 = { 6833380000ffb5d4feffff6833 }


condition:
	$a0
}