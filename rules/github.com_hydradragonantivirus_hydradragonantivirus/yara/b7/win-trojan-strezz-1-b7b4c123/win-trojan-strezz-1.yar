rule Win_Trojan_Strezz_1
{
strings:
	$a0 = { 010300550002000000ffff00000000ac050000050000000103 }


condition:
	$a0
}