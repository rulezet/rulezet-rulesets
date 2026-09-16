rule Win_Trojan_Trojan_245
{
strings:
	$a0 = { 8624032e8b8e050381c108023bc174282d03002e8986 }


condition:
	$a0
}