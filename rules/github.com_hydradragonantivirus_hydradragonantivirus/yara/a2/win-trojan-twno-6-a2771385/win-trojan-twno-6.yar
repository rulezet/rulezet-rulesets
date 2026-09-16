rule Win_Trojan_TWNO_6
{
strings:
	$a0 = { 01010055df43000200ffff000000003b0a00000b0000004203 }


condition:
	$a0
}