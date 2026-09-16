rule Win_Trojan_Steel_8
{
strings:
	$a0 = { 312d03002ea36c012e803e6a010f74228cc88ed8b44033d2b9ab01cd2133c933d28bc0b8 }


condition:
	$a0
}