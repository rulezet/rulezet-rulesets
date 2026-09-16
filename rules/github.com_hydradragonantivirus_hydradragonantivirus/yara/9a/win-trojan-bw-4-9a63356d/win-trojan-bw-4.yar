rule Win_Trojan_BW_4
{
strings:
	$a0 = { 40b92c02908d960601cd21b800429933c9cd21b440b91c008d962f03cd21e9 }


condition:
	$a0
}