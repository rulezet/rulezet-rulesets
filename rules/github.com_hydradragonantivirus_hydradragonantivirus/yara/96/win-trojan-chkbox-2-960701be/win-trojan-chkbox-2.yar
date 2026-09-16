rule Win_Trojan_Chkbox_2
{
strings:
	$a0 = { cd213dffff747f90908cd8488ed88b1e030083eb3e }


condition:
	$a0
}