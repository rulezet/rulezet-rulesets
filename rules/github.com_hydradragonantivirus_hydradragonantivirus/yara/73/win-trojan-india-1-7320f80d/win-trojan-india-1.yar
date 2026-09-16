rule Win_Trojan_India_1
{
strings:
	$a0 = { 5c018b0e5d01cd6d730559e2e6cd18 }


condition:
	$a0
}