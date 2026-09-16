rule Win_Trojan_Multiface_1
{
strings:
	$a0 = { 58c6075ac7470100008947035b8db70000bf00000e1f }


condition:
	$a0
}