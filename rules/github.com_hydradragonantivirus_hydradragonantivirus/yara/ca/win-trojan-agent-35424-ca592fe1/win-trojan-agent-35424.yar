rule Win_Trojan_Agent_35424
{
strings:
	$a0 = { 558bec6aff68986d4100681808410064a1 }

	$a1 = { 2e646c6c }

	$a2 = { 50726f647563744964 }

	$a3 = { 5c352e305c55736572204167656e745c }


condition:
	$a0 and $a1 and $a2 and $a3
}