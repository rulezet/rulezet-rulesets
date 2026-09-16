rule Win_Trojan_BHO_111
{
strings:
	$a0 = { 54494542726f7773657248656c706572466163746f7279 }

	$a1 = { 558bec83c4c4b8000305ace80e005dbcb8000305 }


condition:
	$a0 and $a1
}