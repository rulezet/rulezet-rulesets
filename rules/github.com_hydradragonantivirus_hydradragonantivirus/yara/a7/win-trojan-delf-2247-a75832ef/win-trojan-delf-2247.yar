rule Win_Trojan_Delf_2247
{
strings:
	$a0 = { 558becb90a0000006a006a004975f95153b8887e4000e88dc5ffff33c055689a81400064ff306489 }


condition:
	$a0
}