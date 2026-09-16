rule Win_Trojan_SVC_13
{
strings:
	$a0 = { b9cc06b80040e8c4fd72203dcc06751b }


condition:
	$a0
}