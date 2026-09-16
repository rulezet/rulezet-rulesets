rule Win_Trojan_Lame_3
{
strings:
	$a0 = { ba4559cd16e81300803e6501037442ba6201b43bcd2173ede93600c606650100b44eba5c01cd217301c3b8023d }


condition:
	$a0
}