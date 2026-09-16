rule Win_Trojan_B_94
{
strings:
	$a0 = { c98ed1bc007c8bf48ec18ed9fbfcbf0006b501f2a5e9008ab80102bb007cb90100ba8000e82d }


condition:
	$a0
}