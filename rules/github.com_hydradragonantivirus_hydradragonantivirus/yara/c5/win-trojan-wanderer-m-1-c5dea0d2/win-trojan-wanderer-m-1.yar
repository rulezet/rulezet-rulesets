rule Win_Trojan_Wanderer_M_1
{
strings:
	$a0 = { ffb40f86e090cd213d0101741b33c08ec026813e54006b }


condition:
	$a0
}