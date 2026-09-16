rule Win_Trojan_Rideon_1
{
strings:
	$a0 = { 4515c3b44233c933d2e81100c353b82012cd2fb81612268a1dcd2f5bc39c2eff1e7a03c3e8 }


condition:
	$a0
}