rule Win_Trojan_C_87
{
strings:
	$a0 = { e800005d81ed0700508dbe1d008bf7b9e50190ac34 }


condition:
	$a0
}