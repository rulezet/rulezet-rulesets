rule Win_Trojan_Juntador_14
{
strings:
	$a0 = { 64ff306489208b45f8508b4dfcba34424000b801000080e815ffffff33c05a59596489106825424000 }


condition:
	$a0
}