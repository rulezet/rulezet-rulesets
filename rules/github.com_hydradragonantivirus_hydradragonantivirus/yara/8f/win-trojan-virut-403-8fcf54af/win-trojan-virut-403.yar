rule Win_Trojan_Virut_403
{
strings:
	$a0 = { 6a00e95c5f0000ccff2500204000000000 }

	$a1 = { 741b50647a5f[0-60]472c2b686a }


condition:
	$a0 and $a1
}