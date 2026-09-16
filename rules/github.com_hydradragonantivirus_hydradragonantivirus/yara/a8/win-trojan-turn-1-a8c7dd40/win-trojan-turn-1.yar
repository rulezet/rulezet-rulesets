rule Win_Trojan_Turn_1
{
strings:
	$a0 = { 024233c933d2e81500c3b8004233c933d2e80a00c3b440b92d02e80100c39c2eff1e0501c386e0 }


condition:
	$a0
}