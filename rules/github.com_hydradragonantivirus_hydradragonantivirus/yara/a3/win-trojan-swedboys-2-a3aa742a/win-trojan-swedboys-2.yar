rule Win_Trojan_SwedBoys_2
{
strings:
	$a0 = { 018a27bb02018a0786c40503008bf0b41a8d94c80283c206cd21b44e }


condition:
	$a0
}