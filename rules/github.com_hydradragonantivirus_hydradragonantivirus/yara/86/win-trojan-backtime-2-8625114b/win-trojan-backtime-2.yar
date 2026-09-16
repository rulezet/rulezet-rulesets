rule Win_Trojan_Backtime_2
{
strings:
	$a0 = { 2172193bc1721533c933d2b80042cd21720aba }


condition:
	$a0
}