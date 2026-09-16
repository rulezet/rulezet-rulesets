rule Win_Trojan_Milan_2
{
strings:
	$a0 = { eb02ebefb42acd213c02740bb409bade01cd21b44ccd21 }


condition:
	$a0
}