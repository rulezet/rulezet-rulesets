rule Win_Trojan_ZK_1
{
strings:
	$a0 = { b82135cd2126817f025a4b74722e8c }


condition:
	$a0
}