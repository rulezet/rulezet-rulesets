rule Win_Trojan_Findme_2
{
strings:
	$a0 = { 01a045032ea20101a046032ea20201b97f00bb81002e }


condition:
	$a0
}