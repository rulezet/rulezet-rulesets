rule Win_Trojan_Genesis_1
{
strings:
	$a0 = { 8d96f701b80043cd215133c9b80143cd21b8023d8d96f701 }


condition:
	$a0
}