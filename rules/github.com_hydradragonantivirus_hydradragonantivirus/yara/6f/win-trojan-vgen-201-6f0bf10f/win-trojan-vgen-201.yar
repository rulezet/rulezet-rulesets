rule Win_Trojan_VGEN_201
{
strings:
	$a0 = { 0400cd038db6d402ffd6a40e29e73da69ad61ea282d51ea2a2d41ed0ebf6ebf6e7a78a981e92380fd10b90f492ec91 }


condition:
	$a0
}