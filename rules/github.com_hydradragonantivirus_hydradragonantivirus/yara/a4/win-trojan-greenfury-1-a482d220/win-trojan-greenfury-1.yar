rule Win_Trojan_GreenFury_1
{
strings:
	$a0 = { 01040055c000000100ffff09030000cf020000020000000903 }


condition:
	$a0
}