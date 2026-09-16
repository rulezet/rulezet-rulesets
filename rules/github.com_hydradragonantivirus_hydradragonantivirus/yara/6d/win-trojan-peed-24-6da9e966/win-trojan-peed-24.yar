rule Win_Trojan_Peed_24
{
strings:
	$a0 = { 28c9e83d0000005589e58b }


condition:
	$a0
}