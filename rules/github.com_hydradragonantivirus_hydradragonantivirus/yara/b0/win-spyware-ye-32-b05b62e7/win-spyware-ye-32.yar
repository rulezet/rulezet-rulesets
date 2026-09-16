rule Win_Spyware_ye_32
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]1de327fc385f0abce68b36a0c0e59d }


condition:
	$a0
}