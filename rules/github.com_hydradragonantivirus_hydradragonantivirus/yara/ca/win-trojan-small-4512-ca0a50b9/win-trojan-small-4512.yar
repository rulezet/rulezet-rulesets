rule Win_Trojan_Small_4512
{
strings:
	$a0 = { b821??e?0f2d2164a50f50[0-2]e82?0000 }


condition:
	$a0
}