rule Win_Trojan_Tiny_37
{
strings:
	$a0 = { 69b04df2ae7418b002e82100b18acd69 }


condition:
	$a0
}