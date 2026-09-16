rule Win_Trojan_Loz_11
{
strings:
	$a0 = { 8bfe83c71a[0-1]b9dc062e30052c??47e2f8 }


condition:
	$a0
}