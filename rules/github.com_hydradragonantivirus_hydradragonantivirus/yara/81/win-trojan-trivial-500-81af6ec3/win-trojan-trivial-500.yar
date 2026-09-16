rule Win_Trojan_Trivial_500
{
strings:
	$a0 = { cd21b44febd45db8004ccd212a2e2a00 }


condition:
	$a0
}