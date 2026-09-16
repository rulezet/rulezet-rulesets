rule Win_Trojan_AT_7
{
strings:
	$a0 = { a5b824008ec033ff83ee3a26803d60 }


condition:
	$a0
}