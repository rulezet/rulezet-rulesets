rule Win_Trojan_B_110
{
strings:
	$a0 = { 832e130403cd12b106d3e08ec006b82a }


condition:
	$a0
}