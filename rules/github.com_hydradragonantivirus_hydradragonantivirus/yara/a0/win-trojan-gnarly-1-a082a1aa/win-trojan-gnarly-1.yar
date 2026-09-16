rule Win_Trojan_Gnarly_1
{
strings:
	$a0 = { 2164656c657465[0-1]216d6f76656669[0-1]21636f70796669[0-157]2d2072656d6f7465 }


condition:
	$a0
}