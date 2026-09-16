rule Win_Trojan_IntFF_1
{
strings:
	$a0 = { 33c933d2cdffb91800bae82fb440cdffb8024233c933d2cdffb987021e0e1f8d55ecb440cd }


condition:
	$a0
}