rule Win_Trojan_AutoZip_1
{
strings:
	$a0 = { be009a00005c005589e581ec000c9a3f08be009ac2015c00c6063e0002b003509a59025c00bf64031e57bf0000 }


condition:
	$a0
}