rule Win_Trojan_Mini_14
{
strings:
	$a0 = { 9e0052cd2193061fb43f575a5459cd2150b800429933c9cd2159890e1d0181c16a00b440565acd }


condition:
	$a0
}