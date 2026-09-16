rule Win_Trojan_AFFA_1
{
strings:
	$a0 = { ba0001b92105cd21b8004233c933d2cd21b0e9a21b04a11f042d0300a31c04b440ba1b04b903 }


condition:
	$a0
}