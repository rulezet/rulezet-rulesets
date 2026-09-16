rule Win_Trojan_Kxx_1
{
strings:
	$a0 = { e800005d81ed0300b8b84bcd213dd20474 }


condition:
	$a0
}