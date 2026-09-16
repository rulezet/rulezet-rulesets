rule Win_Trojan_Buzus_40
{
strings:
	$a0 = { 558becb9780000006a006a004975f951535657b8d0c14000e81b87ffff33c055 }


condition:
	$a0
}