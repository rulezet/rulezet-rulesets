rule Win_Trojan_Semtex_1
{
strings:
	$a0 = { 3e8400268b1686008ec226813d9c507519bafffffc8d36 }


condition:
	$a0
}