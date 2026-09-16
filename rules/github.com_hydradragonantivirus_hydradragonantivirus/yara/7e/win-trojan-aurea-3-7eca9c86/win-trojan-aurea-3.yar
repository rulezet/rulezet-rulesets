rule Win_Trojan_Aurea_3
{
strings:
	$a0 = { 2600fc8a260e00b967028a0432c4880446e2f7 }


condition:
	$a0
}