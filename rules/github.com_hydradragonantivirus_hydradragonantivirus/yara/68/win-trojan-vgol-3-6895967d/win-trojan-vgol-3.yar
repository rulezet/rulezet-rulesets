rule Win_Trojan_VGOL_3
{
strings:
	$a0 = { 29d2b9fa06e837003dfa067527803efa064d740ab90700b440ba0a04cd21b90000b8004229d2 }


condition:
	$a0
}