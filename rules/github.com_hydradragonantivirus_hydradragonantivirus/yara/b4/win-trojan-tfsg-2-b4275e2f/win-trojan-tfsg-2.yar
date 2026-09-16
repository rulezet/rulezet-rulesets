rule Win_Trojan_TFSG_2
{
strings:
	$a0 = { 1eb90004b401cd16e2fa0e1f90be2f00a12c00fcb9bb019090300446d1c802c4e2f7 }


condition:
	$a0
}