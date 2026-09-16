rule Win_Trojan_Andrev_1
{
strings:
	$a0 = { 7624b002b9010033d281c353038bf30e1fcd2572109db0028bdeb9010033d2c6441a00cd26 }


condition:
	$a0
}