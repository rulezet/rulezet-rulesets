rule Win_Trojan_Clisti_1
{
strings:
	$a0 = { e9a600eb1deb01900e1fe800005b83c30eb9a000f7174343e2fac3 }


condition:
	$a0
}