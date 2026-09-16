rule Win_Trojan_Uruk_2
{
strings:
	$a0 = { 511e3d004b7503e836001f595b5a58ebe7b003cfbb }


condition:
	$a0
}