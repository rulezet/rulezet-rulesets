rule Win_Trojan_Ghost_4
{
strings:
	$a0 = { b44fcd217302eb9f8b847400241f3c }


condition:
	$a0
}