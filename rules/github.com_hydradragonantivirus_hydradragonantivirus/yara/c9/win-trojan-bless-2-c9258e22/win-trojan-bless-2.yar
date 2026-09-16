rule Win_Trojan_Bless_2
{
strings:
	$a0 = { 426d50229e690baad882cca08fac36a8fe0442dad0d062641b01c0b90f63941fd09e4f93ebb45ac7d7cbb9d1612f }


condition:
	$a0
}