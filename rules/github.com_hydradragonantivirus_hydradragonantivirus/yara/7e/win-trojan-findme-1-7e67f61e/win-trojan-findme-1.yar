rule Win_Trojan_Findme_1
{
strings:
	$a0 = { 01a0ee022ea20101a0ef022ea20201b97f00bb81002e }


condition:
	$a0
}