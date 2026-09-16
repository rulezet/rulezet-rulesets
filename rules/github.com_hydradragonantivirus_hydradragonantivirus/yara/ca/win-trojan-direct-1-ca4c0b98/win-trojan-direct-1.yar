rule Win_Trojan_Direct_1
{
strings:
	$a0 = { 21ba8000b90100b811039c9a6d8a00f0fec680e607 }


condition:
	$a0
}