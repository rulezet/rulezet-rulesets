rule Win_Trojan_Wannabe_1
{
strings:
	$a0 = { 01010055a607000000ffff3b030000a2010000060000003b03 }


condition:
	$a0
}