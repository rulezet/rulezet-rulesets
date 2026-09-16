rule Win_Trojan_Peed_345
{
strings:
	$a0 = { 5f5e33c05b[0-1]c36a00ff1504604000c3 }


condition:
	$a0
}