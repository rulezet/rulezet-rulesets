rule Win_Trojan_PZ_2
{
strings:
	$a0 = { 028db68e018bfeb9cc0090ad2e8b96050133c2abad2e8b96070133c2abe881ffe2e9e93c02 }


condition:
	$a0
}