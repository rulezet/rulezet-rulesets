rule Win_Trojan_Crasher_1
{
strings:
	$a0 = { 1233d2b43080c4102e8b0ef70081c1b701cd21b44e80ec10cd21b449cd21b824252e8b16fd002e }


condition:
	$a0
}