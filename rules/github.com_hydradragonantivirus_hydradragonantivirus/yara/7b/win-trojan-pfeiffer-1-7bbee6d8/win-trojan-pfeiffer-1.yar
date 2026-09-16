rule Win_Trojan_Pfeiffer_1
{
strings:
	$a0 = { c6060001e9b82e01bb01012d030133c1c707 }


condition:
	$a0
}