rule Win_Trojan_NV71_1
{
strings:
	$a0 = { 8cda83c2102e0116030033c08ed8813e860300b875 }


condition:
	$a0
}