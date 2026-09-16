rule Win_Trojan_DSA_1
{
strings:
	$a0 = { 0150b401c0e406b90701ba0001cd21b8004233c999cd }


condition:
	$a0
}