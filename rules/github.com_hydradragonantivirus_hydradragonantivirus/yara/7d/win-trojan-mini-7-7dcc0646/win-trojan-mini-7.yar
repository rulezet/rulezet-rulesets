rule Win_Trojan_Mini_7
{
strings:
	$a0 = { 9ecd2193b43fb25cfec65459cd21055c0050b800429933c9cd2159b440fec6cd21b43ecd21b4 }


condition:
	$a0
}