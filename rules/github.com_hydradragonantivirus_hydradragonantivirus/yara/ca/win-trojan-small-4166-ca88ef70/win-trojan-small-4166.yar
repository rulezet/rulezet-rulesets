rule Win_Trojan_Small_4166
{
strings:
	$a0 = { 69d559b89bf269efeb02bd8c69 }


condition:
	$a0
}