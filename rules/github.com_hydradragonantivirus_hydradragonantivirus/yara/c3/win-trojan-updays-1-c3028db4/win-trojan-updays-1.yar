rule Win_Trojan_Updays_1
{
strings:
	$a0 = { 433a5c61663332643362305c62363632656634392e657865 }


condition:
	$a0
}