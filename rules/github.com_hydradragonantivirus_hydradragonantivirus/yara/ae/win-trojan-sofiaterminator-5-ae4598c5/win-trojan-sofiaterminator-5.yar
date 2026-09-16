rule Win_Trojan_SofiaTerminator_5
{
strings:
	$a0 = { ee03898469031e29c08ed8813e7304fb007503e9b100c7067304fb000e58488ed8812e03008000812e12008000a1 }


condition:
	$a0
}