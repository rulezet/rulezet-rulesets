rule Win_Trojan_Wisconson_1
{
strings:
	$a0 = { 8b0e0601be08018a0434ff880446e2f7 }


condition:
	$a0
}