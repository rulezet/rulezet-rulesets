rule Win_Trojan_Dirty_2
{
strings:
	$a0 = { 020055a6000002000100bd0e00006d00000004000000bd0e }


condition:
	$a0
}