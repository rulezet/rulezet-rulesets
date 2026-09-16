rule Win_Trojan_Evasor_1
{
strings:
	$a0 = { 0195b9ffffeb0690b8004ccd21e2f6b04ce84100ba6001b90700cd217303eb3390b03be82f004040ba9e00cd21 }


condition:
	$a0
}