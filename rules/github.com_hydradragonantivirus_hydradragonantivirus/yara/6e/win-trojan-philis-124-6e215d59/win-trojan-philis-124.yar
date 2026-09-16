rule Win_Trojan_Philis_124
{
strings:
	$a0 = { 33c133c1606061e80000000056be03c100005e530f }


condition:
	$a0
}