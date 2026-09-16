rule Win_Trojan_Emmie_2
{
strings:
	$a0 = { 2003e800005dfc8d760eb9020531044646eb00 }


condition:
	$a0
}