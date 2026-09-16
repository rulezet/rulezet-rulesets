rule Win_Trojan_Agent_35411
{
strings:
	$a0 = { e82800000000650000cf000000fa0000000000358603a7 }

	$a1 = { 3939303434363830332d31 }


condition:
	$a0 and $a1
}