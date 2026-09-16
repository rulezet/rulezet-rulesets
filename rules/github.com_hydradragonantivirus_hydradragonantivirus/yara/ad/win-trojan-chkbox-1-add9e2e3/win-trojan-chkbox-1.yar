rule Win_Trojan_Chkbox_1
{
strings:
	$a0 = { cd213dffff747f90908cd8488ed88b1e030083eb3b }


condition:
	$a0
}