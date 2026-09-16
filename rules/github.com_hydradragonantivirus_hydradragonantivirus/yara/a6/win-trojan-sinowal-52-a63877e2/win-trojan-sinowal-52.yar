rule Win_Trojan_Sinowal_52
{
strings:
	$a0 = { 6a006a006a006a006a006a006a0068a49040009c5090 }

	$a1 = { 295d372e297b3f2d34322d2f335d2c283569 }


condition:
	$a0 and $a1
}