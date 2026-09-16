rule Win_Trojan_Shoe_1
{
strings:
	$a0 = { 98345f0aa1bb086a3ac2aa8935958777b77cad49a8ff3654 }


condition:
	$a0
}