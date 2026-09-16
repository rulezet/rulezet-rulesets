rule Win_Trojan_5824_1
{
strings:
	$a0 = { 94005589e581ec0202bfc7000e57bf712f1e57b8ff00509a2b039400bf712f1e57e83dffbfcf000e57bf672f1e }


condition:
	$a0
}