rule Win_Trojan_Dutch_4
{
strings:
	$a0 = { d2b92b02cd213bc1585a7523e86900 }


condition:
	$a0
}