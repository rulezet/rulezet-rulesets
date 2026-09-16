rule Win_Trojan_Squawk_1
{
strings:
	$a0 = { 8edba10100030603003b061200722f812e03000001812e }


condition:
	$a0
}