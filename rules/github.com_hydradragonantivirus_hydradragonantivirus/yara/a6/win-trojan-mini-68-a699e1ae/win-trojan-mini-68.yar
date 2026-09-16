rule Win_Trojan_Mini_68
{
strings:
	$a0 = { 99b29ecd2193b43fba5301905459cd21055300905033c9f7e1b442cd2159b4405a52cd21b4 }


condition:
	$a0
}