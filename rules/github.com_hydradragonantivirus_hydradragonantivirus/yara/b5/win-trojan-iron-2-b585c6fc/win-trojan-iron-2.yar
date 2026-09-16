rule Win_Trojan_Iron_2
{
strings:
	$a0 = { 0f01b440cd21b800429933c9cd218b8640022d03008986 }


condition:
	$a0
}