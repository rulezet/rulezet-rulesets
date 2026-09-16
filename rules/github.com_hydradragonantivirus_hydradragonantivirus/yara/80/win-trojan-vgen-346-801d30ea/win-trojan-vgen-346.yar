rule Win_Trojan_VGEN_346
{
strings:
	$a0 = { 1fbd0000be1b0003f5b98706e88706061f069ce85a01e860007219ba4559b801facd16bf554ebe414eb802fecd2f0e }


condition:
	$a0
}