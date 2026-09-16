rule Win_Trojan_Small_4280
{
strings:
	$a0 = { e8??0000006a01e8[0-255]5860505b66bb0000[0-4]e9??ffffff }


condition:
	$a0
}