rule Win_Trojan_Satanic_1
{
strings:
	$a0 = { 050055fd01000300ffff7008000004020000030000003103 }


condition:
	$a0
}