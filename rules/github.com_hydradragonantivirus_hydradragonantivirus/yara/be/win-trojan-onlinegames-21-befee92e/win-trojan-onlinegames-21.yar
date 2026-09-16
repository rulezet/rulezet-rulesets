rule Win_Trojan_Onlinegames_21
{
strings:
	$a0 = { 33c0740aa64aaed6bc6aaad8ad40576aff5f2bcf5f81e960583d2281c160583d2249e96371 }


condition:
	$a0
}