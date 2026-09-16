rule Win_Trojan_Small_4269
{
strings:
	$a0 = { e8??0000006a00e8??000000[0-255]60505b66bb0000e9??ffffff01dd[0-10]8d??222725038d08 }


condition:
	$a0
}