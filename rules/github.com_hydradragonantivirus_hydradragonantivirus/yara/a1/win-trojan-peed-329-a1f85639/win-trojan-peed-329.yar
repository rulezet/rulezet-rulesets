rule Win_Trojan_Peed_329
{
strings:
	$a0 = { 8daa4223aa00e82e00000051eb10b8ffffffff8d40f883c00529c249eb2ab996 }


condition:
	$a0
}