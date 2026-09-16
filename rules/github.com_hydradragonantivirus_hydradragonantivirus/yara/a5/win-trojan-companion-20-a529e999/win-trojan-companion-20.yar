rule Win_Trojan_Companion_20
{
strings:
	$a0 = { 7504b8fecacf3d004b7403e9f300e9f500fc575606 }


condition:
	$a0
}