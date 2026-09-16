rule Win_Trojan_Primit_1
{
strings:
	$a0 = { 010100558e00000000ffff70080000cc4a0000030000007008 }


condition:
	$a0
}