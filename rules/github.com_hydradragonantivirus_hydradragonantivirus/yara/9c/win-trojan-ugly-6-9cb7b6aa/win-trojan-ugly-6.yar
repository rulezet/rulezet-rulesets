rule Win_Trojan_Ugly_6
{
strings:
	$a0 = { 33c08ed0bc007cbb187cb996010e1f51803700434975f9 }


condition:
	$a0
}