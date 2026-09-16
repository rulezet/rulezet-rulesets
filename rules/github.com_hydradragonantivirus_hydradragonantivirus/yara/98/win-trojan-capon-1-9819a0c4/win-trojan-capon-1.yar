rule Win_Trojan_Capon_1
{
strings:
	$a0 = { cd45cccccd20c03330ffcdffcd01ffff }


condition:
	$a0
}