rule Win_Trojan_Buzus_45
{
strings:
	$a0 = { 558becb9060000006a006a004975f951535657b8cc674000e8bbd2ffff8b3dac87400033c05568147540 }


condition:
	$a0
}