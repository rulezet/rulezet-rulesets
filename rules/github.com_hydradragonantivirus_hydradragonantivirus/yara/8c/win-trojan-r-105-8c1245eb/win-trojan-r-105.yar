rule Win_Trojan_R_105
{
strings:
	$a0 = { d609d9917a29694649f10fae4815a0ab1f41582180fbf78fc419a9f7e7a4aeb9 }


condition:
	$a0
}