rule Win_Trojan_Small_4561
{
strings:
	$a0 = { 40006845234500685232980068625446046a012d32523434ff90 }


condition:
	$a0
}