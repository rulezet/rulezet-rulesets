rule Win_Trojan_Small_4525
{
strings:
	$a0 = { 8da8??32420068533445006a006a00ff15??d1420029d529c5e84300000055e8 }


condition:
	$a0
}