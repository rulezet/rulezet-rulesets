rule Win_Trojan_Ascii_222_239_255_114_1
{
strings:
	$a0 = { 3232322e3233392e3235352e313134 }


condition:
	$a0
}