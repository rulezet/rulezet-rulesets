rule Win_Trojan_Steel_6
{
strings:
	$a0 = { fa77312d03002ea36a012e803e68010f74228cc88ed8b44033d2b99701cd2133c933d28bc0b8 }


condition:
	$a0
}