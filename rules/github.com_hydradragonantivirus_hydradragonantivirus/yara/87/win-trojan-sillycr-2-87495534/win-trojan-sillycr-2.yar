rule Win_Trojan_SillyCR_2
{
strings:
	$a0 = { a35302ba5502b95501b440cd2131c931d2b80042cd21b440ba0001b95501cd21b43efbcd212ec5 }


condition:
	$a0
}