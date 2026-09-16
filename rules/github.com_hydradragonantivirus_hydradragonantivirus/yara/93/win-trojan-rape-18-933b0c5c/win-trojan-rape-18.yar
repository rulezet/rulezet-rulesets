rule Win_Trojan_Rape_18
{
strings:
	$a0 = { b433d2b440b9eb0290cd6972a85a5983e1e083c91feb025a59b80157cd69 }


condition:
	$a0
}