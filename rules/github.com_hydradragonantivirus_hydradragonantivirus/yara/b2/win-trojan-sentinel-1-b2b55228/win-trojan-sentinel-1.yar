rule Win_Trojan_Sentinel_1
{
strings:
	$a0 = { 89e583ec128c5ef855e815fdb8cf0d }


condition:
	$a0
}