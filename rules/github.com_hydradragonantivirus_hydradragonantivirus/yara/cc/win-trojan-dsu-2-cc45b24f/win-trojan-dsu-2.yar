rule Win_Trojan_DSU_2
{
strings:
	$a0 = { 5bb9b30283c311902e8137710e4343e2f7 }


condition:
	$a0
}