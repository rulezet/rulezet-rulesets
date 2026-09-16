rule Win_Trojan_Empire_3
{
strings:
	$a0 = { 0331db41e823ffa0a801403c16720230c0a2a801 }


condition:
	$a0
}