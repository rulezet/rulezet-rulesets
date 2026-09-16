rule Win_Trojan_Gotcha_13
{
strings:
	$a0 = { 3ddada742880fc3d740a3d006c740580fc4b7513061e50 }


condition:
	$a0
}