rule Win_Trojan_Mini_70
{
strings:
	$a0 = { 1fba5401905459cd21803e5401927414055400905033c9f7e1b442cd2159b440fec6cd210e }


condition:
	$a0
}