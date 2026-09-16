rule Win_Trojan_Sentinel_5
{
strings:
	$a0 = { 89ec5dc202005589e583ec128c5e }


condition:
	$a0
}