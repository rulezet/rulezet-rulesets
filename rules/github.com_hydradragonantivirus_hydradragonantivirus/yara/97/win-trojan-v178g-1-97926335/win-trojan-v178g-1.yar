rule Win_Trojan_V178G_1
{
strings:
	$a0 = { 018b85a60189048b85a801894402b41abab601 }


condition:
	$a0
}