rule Win_Trojan_Delf_2270
{
strings:
	$a0 = { 558bec83c4f0b860960100e8f8b1ffff33 }


condition:
	$a0
}