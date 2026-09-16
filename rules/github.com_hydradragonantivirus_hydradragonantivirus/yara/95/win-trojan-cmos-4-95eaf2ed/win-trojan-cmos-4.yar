rule Win_Trojan_CMOS_4
{
strings:
	$a0 = { b111f6c2807536b52826807f15fc7302 }


condition:
	$a0
}