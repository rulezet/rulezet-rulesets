rule Win_Trojan_TWNO_5
{
strings:
	$a0 = { 010100558e45000000ffff000000008c060000090000006203 }


condition:
	$a0
}