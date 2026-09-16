rule Win_Trojan_SdBot_3995
{
strings:
	$a0 = { 7422ca54bd05998d6ad12e018ca891cedabccd9fc42b0dc568d82054e675aee68f64fc54a0541dccff3282f2cbafe1446f4bd40ce0b8b155b3914d5f8e341299826055b1 }


condition:
	$a0
}