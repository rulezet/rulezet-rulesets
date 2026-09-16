rule Win_Trojan_Stoned_17
{
strings:
	$a0 = { a1130448a31304b106d3e08ec0a3f07cb900020e1f33ffbe007cfcf3a4b83200a34c008c064e00 }


condition:
	$a0
}