rule Win_Trojan_HaryAnto_1
{
strings:
	$a0 = { d3e8bb3e01890740b90400d3e0505a33c9b800428b }


condition:
	$a0
}