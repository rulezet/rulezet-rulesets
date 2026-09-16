rule Win_Trojan_Reboot_5
{
strings:
	$a0 = { 72756e5c646c7262222c73797364697226225c646c72622e766273 }


condition:
	$a0
}