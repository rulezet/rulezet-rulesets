rule Win_Trojan_Mini_76
{
strings:
	$a0 = { 01905459cd215087d6ac3c92587414055c00905033c9f7e1b442cd2159b4405a52cd21b44feb }


condition:
	$a0
}