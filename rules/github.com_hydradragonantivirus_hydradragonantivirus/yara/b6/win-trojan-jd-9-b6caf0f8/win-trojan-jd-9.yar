rule Win_Trojan_JD_9
{
strings:
	$a0 = { 02b104b43fcd21803eba024d7446 }


condition:
	$a0
}