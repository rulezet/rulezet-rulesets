rule Win_Trojan_Tony_2
{
strings:
	$a0 = { 12cd2f33f6ad3d2e3a74064e75f7e98c00ac3c2675ef83ee038bd6b80325cd210e1fc6067f00cfb82425ba7f00cc8cc880c4108ec0be000133ff8bcef3 }


condition:
	$a0
}