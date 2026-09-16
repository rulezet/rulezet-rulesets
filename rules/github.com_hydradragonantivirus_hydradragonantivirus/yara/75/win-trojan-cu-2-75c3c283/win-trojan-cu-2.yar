rule Win_Trojan_CU_2
{
strings:
	$a0 = { 434f2d03002ea31e03050300b440ba0000b92704cd21b8004233c999cd21b440ba1d03b9 }


condition:
	$a0
}