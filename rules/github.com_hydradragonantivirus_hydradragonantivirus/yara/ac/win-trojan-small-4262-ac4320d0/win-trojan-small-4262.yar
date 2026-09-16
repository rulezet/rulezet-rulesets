rule Win_Trojan_Small_4262
{
strings:
	$a0 = { e8d5000000e91500000055545db8c81cd9d98d803827272653 }


condition:
	$a0
}