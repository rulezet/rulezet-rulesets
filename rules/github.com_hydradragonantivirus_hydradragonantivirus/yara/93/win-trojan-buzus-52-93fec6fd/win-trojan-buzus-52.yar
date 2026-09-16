rule Win_Trojan_Buzus_52
{
strings:
	$a0 = { 558becb91b0000006a006a004975f951535657b8383f4000e84fe3ffff8b3d98 }


condition:
	$a0
}