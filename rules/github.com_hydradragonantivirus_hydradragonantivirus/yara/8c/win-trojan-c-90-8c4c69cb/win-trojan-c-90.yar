rule Win_Trojan_C_90
{
strings:
	$a0 = { b8008bf0eb44b8270050b85c0350ff34e88c0a83c406eb2a833e7803007c1b7f08813e7603f811 }


condition:
	$a0
}