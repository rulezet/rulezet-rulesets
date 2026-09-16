rule Win_Trojan_Already_1
{
strings:
	$a0 = { 017505b8014ccd2189163701890e3901ba3b0133c9b43ccd218bd8ba0001b94700b440cd21 }


condition:
	$a0
}