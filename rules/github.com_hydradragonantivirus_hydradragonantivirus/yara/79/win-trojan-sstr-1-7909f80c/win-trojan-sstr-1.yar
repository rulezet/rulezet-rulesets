rule Win_Trojan_SSTR_1
{
strings:
	$a0 = { 5e5381ee0d01562e8a160101b9b10230942601fec246e2f7 }


condition:
	$a0
}