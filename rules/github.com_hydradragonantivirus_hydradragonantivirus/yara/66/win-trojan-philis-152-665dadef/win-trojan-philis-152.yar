rule Win_Trojan_Philis_152
{
strings:
	$a0 = { 558bec83c4f0b800704100e806003e28e80600c348e8060027148bc000000000 }


condition:
	$a0
}