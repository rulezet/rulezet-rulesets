rule Win_Trojan_O_6
{
strings:
	$a0 = { 0403066e0435aa55d3c903c124033c00750cfac70620 }


condition:
	$a0
}