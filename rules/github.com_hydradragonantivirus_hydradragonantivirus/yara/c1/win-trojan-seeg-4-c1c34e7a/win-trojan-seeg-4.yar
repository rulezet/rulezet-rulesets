rule Win_Trojan_Seeg_4
{
strings:
	$a0 = { 93deda2cd1bb3405d265df5ac64c0c9addaa3232c2dada375bc7fbdcc5e00db5c5dc91fc67902fdc }


condition:
	$a0
}