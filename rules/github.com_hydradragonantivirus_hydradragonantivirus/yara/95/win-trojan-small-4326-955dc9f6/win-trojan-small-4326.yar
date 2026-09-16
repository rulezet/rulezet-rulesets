rule Win_Trojan_Small_4326
{
strings:
	$a0 = { 60e8??000000[0-255]83f8010f84100000008d5c24588b5c23006629db }


condition:
	$a0
}