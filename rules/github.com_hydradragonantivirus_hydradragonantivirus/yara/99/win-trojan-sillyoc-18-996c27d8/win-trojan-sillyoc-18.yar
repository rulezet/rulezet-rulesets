rule Win_Trojan_SillyOC_18
{
strings:
	$a0 = { eb7426803d4d7421b8004233c933d2cd21b440b1ae9090ba0001cd21b801578b16a8018b0e }


condition:
	$a0
}