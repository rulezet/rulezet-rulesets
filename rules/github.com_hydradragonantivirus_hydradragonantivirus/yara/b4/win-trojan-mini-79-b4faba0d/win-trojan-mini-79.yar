rule Win_Trojan_Mini_79
{
strings:
	$a0 = { 01905459cd21055d00905033c9f7e1b442cd2159b4405a52cd2186ceb8014399b29ecd21b44f }


condition:
	$a0
}