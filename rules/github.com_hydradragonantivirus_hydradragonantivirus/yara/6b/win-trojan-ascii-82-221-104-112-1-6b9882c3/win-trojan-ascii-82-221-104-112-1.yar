rule Win_Trojan_Ascii_82_221_104_112_1
{
strings:
	$a0 = { 38322e3232312e3130342e313132 }


condition:
	$a0
}