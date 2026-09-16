rule Win_Trojan_Irish_3
{
strings:
	$a0 = { 010400550001000200ffff0103000014040000020000006a08 }


condition:
	$a0
}