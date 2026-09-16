rule Win_Trojan_Lazard_2
{
strings:
	$a0 = { 681310400060e8000000005d81ed0b204000e8110300008d }


condition:
	$a0
}