rule Win_Trojan_Noodle_1
{
strings:
	$a0 = { 010300550000000000ffff09030000bf510000020000000903 }


condition:
	$a0
}