rule Win_Trojan_Delf_2268
{
strings:
	$a0 = { 558bec83c4c4b8fc0a4200e8984bfeff833d6456 }


condition:
	$a0
}