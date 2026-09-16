rule Win_Trojan_Small_169
{
strings:
	$a0 = { b1d7fec48bf0fec48bf80e5651560e06681802f3a4cbae75114f8edbbe840056faa5a55fb046ab8cd8ab585f5e81 }


condition:
	$a0
}