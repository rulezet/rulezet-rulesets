rule Win_Trojan_Pandemonium_1
{
strings:
	$a0 = { 40b9f00599eb30b0003db001b457e8adfb80fec8c3b43f }


condition:
	$a0
}