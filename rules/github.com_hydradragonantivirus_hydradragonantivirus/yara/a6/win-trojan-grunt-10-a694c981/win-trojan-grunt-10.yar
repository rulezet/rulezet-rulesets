rule Win_Trojan_Grunt_10
{
strings:
	$a0 = { a601000000ffff70080000ec020000040000007008 }


condition:
	$a0
}