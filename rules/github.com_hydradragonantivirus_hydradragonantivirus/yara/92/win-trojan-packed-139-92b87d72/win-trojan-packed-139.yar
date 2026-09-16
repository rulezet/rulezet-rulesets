rule Win_Trojan_Packed_139
{
strings:
	$a0 = { 64ff3530000000e9 }

	$a1 = { 68f89d0100f71424f71424e9????ffff }


condition:
	$a0 and $a1
}