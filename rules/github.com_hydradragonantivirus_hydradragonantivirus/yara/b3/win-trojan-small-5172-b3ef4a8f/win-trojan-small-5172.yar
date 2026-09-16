rule Win_Trojan_Small_5172
{
strings:
	$a0 = { 41549761b1ce023dcce0324e81cb58c87633147d41548f61bdce023dabcb8bd1654f063d415657614d3503cacdef724041cb8bc1654b063d416c5b4d81cb6c }


condition:
	$a0
}