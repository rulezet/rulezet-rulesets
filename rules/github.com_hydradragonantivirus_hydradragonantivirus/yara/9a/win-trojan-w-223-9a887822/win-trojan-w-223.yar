rule Win_Trojan_W_223
{
strings:
	$a0 = { 66813e4d5a740881ee00000100ebee8bfe8bd6037e3c66813f5045 }


condition:
	$a0
}