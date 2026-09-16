rule Win_Trojan_Khizhnjak_Gen_1
{
strings:
	$a0 = { b44ecd21731ae9????8b1e????b43ecd21c706????ffffb44fcd217303 }


condition:
	$a0
}