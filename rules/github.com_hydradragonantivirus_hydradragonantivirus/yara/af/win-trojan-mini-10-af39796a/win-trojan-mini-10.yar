rule Win_Trojan_Mini_10
{
strings:
	$a0 = { 9e0052cd2193061fb43f575a5459cd2150b800429933c9cd2159890e1f0183c16490b440565acd }


condition:
	$a0
}