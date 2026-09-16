rule Win_Trojan_Striker_3
{
strings:
	$a0 = { b8003f8bd583c218b90d00cd21a19a00 }


condition:
	$a0
}