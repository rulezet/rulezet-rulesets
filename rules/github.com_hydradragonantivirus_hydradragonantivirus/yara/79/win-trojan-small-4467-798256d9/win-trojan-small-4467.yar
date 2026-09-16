rule Win_Trojan_Small_4467
{
strings:
	$a0 = { ff74241c588d80??647704506862343504e8670000004050 }


condition:
	$a0
}