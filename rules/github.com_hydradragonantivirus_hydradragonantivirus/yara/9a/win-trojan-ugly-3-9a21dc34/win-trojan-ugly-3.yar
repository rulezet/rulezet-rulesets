rule Win_Trojan_Ugly_3
{
strings:
	$a0 = { c08ed0bc007c0e1fb99e01bb177c5180370043e2fa }


condition:
	$a0
}