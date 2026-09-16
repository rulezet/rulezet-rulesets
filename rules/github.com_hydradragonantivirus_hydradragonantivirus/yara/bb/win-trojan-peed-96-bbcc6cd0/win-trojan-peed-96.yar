rule Win_Trojan_Peed_96
{
strings:
	$a0 = { e8120000005589e5890189d88b5d086bdb0343c9c2040029d287d15a8d1d14b5 }


condition:
	$a0
}