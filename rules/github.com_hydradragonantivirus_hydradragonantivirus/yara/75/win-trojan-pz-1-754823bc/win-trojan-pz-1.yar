rule Win_Trojan_PZ_1
{
strings:
	$a0 = { c05d81ed05010e0e1f078db62c018bfeb98801902e8b960501ad33c2abe2fae91c02 }


condition:
	$a0
}