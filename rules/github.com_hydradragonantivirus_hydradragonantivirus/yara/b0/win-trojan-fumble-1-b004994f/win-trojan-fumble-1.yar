rule Win_Trojan_Fumble_1
{
strings:
	$a0 = { 023dbaee00cd217303e9b400894410 }


condition:
	$a0
}