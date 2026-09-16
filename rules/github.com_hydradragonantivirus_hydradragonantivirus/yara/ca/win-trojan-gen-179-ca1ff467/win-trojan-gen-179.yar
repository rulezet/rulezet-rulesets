rule Win_Trojan_Gen_179
{
strings:
	$a0 = { 500089e581ec0002c606377e00bf74000e57bf3d7e1e57b80e00509a90035000bf7e000e57b83f0050bf0a011e }


condition:
	$a0
}