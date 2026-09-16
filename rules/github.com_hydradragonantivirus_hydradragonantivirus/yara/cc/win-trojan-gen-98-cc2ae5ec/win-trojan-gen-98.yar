rule Win_Trojan_Gen_98
{
strings:
	$a0 = { f3a4b81c35cd2181fb450275080e }


condition:
	$a0
}