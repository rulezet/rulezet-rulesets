rule Win_Trojan_Packed_138
{
strings:
	$a0 = { 64ff3530000000e9 }

	$a1 = { 905?83c40868????????f71424f71424e8????000090??83c408 }


condition:
	$a0 and $a1
}