rule Win_Trojan_Loz_12
{
strings:
	$a0 = { 8bfe83c71a[0-1]b927082e000504??47e2f8 }


condition:
	$a0
}