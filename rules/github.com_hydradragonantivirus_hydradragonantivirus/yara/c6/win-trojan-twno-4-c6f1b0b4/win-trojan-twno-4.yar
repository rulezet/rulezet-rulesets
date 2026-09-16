rule Win_Trojan_TWNO_4
{
strings:
	$a0 = { 010100558e00000000ffff0a030000b4050000070000003203 }


condition:
	$a0
}