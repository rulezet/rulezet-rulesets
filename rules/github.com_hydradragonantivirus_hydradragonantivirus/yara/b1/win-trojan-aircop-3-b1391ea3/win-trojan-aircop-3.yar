rule Win_Trojan_Aircop_3
{
strings:
	$a0 = { 1e53ff0e1304cd12b106d3e08ec087064e00a3 }


condition:
	$a0
}