rule Win_Trojan_Sankei_5
{
strings:
	$a0 = { e8000000005d81ed051040008db528104000b98906000056 }


condition:
	$a0
}