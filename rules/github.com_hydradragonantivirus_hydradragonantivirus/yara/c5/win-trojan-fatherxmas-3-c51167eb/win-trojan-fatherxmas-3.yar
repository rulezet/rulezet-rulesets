rule Win_Trojan_FatherXmas_3
{
strings:
	$a0 = { 0106b42fcd21891c8c440207ba5f00 }


condition:
	$a0
}