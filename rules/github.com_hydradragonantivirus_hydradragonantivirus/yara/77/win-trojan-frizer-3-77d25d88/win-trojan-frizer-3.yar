rule Win_Trojan_Frizer_3
{
strings:
	$a0 = { 60061e33c08ed8bb0400ff37ff77020e8f4702c7077f01bb0c00ff37ff77020e8f4702c707fd010e1f9c580d000150 }


condition:
	$a0
}