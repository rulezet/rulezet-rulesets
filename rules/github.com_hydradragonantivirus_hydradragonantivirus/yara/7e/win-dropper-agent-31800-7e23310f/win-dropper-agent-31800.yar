rule Win_Dropper_Agent_31800
{
strings:
	$a0 = { b8f83c4000ba0a000000e80bfeffff8b45cce86bf7ffff8946208b0650e8d0fbffff }


condition:
	$a0
}