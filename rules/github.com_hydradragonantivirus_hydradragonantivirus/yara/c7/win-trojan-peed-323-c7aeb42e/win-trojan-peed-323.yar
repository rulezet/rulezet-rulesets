rule Win_Trojan_Peed_323
{
strings:
	$a0 = { bd1256fa00eb6551eb10b8ffffffff8d40f883c00529c249eb60b92c01000089 }


condition:
	$a0
}