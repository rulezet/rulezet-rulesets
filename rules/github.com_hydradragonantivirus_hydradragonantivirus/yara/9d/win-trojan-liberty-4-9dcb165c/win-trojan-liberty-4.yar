rule Win_Trojan_Liberty_4
{
strings:
	$a0 = { 01baffff1f1ecd2107060e1fbf00 }


condition:
	$a0
}