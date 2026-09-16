rule Win_Trojan_VGEN_488
{
strings:
	$a0 = { fc1ee8de007409b1c1b80100d3e085c07503e98600e85e04b80058cd2150b8015850bb8200cd21b80258cd21b40050 }


condition:
	$a0
}