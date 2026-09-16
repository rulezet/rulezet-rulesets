rule Win_Trojan_Lunch_2
{
strings:
	$a0 = { b44eeb02b44fcd217303e986003d }


condition:
	$a0
}