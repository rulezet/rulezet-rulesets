rule Win_Trojan_Bzub_8
{
strings:
	$a0 = { 75726a333472386834386600633a5c6a776965306639336a333200 }


condition:
	$a0
}