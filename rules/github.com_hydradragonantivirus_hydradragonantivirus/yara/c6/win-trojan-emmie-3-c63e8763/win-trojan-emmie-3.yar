rule Win_Trojan_Emmie_3
{
strings:
	$a0 = { e800005dfc8d760eb9020531044646eb00 }


condition:
	$a0
}