rule Win_Trojan_Zeprox_1
{
strings:
	$a0 = { 503a5c6d61696e74616e63655c636f6e636570745c7265636f6e }


condition:
	$a0
}