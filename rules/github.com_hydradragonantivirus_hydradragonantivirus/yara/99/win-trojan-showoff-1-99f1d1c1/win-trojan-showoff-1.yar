rule Win_Trojan_Showoff_1
{
strings:
	$a0 = { 0600558e02000000ffff0000000092040000050000000103 }


condition:
	$a0
}