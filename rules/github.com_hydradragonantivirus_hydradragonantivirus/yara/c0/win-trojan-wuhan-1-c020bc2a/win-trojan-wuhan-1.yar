rule Win_Trojan_Wuhan_1
{
strings:
	$a0 = { 0d8bca8b1e3401b440ba00019cff1e2801b4408b0e45018b1e3401ba0001e8b9fc9cff1e28 }


condition:
	$a0
}