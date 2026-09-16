rule Win_Trojan_VGEN_437
{
strings:
	$a0 = { 018da6e7021e06b8d59a33c98ed99cff1e84000e1f3dd49a7502eb41b82135cd21899ebf028c86c102b80043cd }


condition:
	$a0
}