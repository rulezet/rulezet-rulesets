rule Win_Trojan_Alabama_3
{
strings:
	$a0 = { 8cdd33db8edb8b070b47027474891f89 }


condition:
	$a0
}