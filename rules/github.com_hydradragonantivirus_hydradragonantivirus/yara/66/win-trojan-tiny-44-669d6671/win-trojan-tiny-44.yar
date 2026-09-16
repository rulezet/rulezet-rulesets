rule Win_Trojan_Tiny_44
{
strings:
	$a0 = { beff00037402bf00015750a5a5bf0406 }


condition:
	$a0
}