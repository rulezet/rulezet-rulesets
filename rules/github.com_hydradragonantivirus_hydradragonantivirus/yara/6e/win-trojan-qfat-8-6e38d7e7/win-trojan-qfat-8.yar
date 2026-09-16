rule Win_Trojan_QFat_8
{
strings:
	$a0 = { e64358e6428ac4e642e4610c03e661adb91027e2fe4875f8e46124fce661b98813e2feebd1eb }


condition:
	$a0
}