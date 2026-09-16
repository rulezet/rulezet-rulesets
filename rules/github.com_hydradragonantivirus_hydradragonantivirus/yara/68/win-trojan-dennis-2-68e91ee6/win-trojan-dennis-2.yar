rule Win_Trojan_Dennis_2
{
strings:
	$a0 = { 33c08ec026803e1904dd744626c6061904dd8cd8488ed88b16030083ea248916030003c2408ec033ff0e1fbe08 }


condition:
	$a0
}