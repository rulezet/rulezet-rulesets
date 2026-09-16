rule Win_Trojan_SK_3
{
strings:
	$a0 = { 20b80300cd1051e800005e83ee09 }


condition:
	$a0
}