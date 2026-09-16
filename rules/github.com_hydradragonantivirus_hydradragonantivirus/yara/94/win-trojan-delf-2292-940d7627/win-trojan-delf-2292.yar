rule Win_Trojan_Delf_2292
{
strings:
	$a0 = { 558bec83c4f053b8382b4000e87fe4ffffbb05010000b8004e4000c60000404b }


condition:
	$a0
}