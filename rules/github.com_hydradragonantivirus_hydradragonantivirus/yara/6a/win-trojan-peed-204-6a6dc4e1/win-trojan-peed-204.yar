rule Win_Trojan_Peed_204
{
strings:
	$a0 = { 89c379255589e55189e68b5d188d63045089f4e2f3592b55082b550c03551003 }


condition:
	$a0
}