rule Win_Trojan_MBR_1
{
strings:
	$a0 = { 1fa1130448a31304b106d3e08ec02ea3337cba8000b9020033dbb80202cd13730633c0cd13ebf1 }


condition:
	$a0
}