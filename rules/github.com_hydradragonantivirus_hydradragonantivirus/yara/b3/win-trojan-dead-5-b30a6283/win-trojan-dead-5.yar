rule Win_Trojan_Dead_5
{
strings:
	$a0 = { b91000f3a4c333d252b8030033dbb94000cd26585a83c2400bd275ecc3558bec502ea16c05 }


condition:
	$a0
}