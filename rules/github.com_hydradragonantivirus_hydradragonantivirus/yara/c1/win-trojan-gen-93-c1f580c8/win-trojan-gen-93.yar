rule Win_Trojan_Gen_93
{
strings:
	$a0 = { 408b0ed4018b167a02cd21b80157b90000cd21eb85b43ecd21bfbc00b94400be9601f3a4bfbc00 }


condition:
	$a0
}