rule Win_Trojan_Mini_83
{
strings:
	$a0 = { cd2193b43fb2639090fec65459cd210563009050b800429933c9cd2159b440fec6cd21b43ecd }


condition:
	$a0
}