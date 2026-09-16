rule Win_Trojan_Bancos_1849
{
strings:
	$a0 = { 96cd1bc46d5d2abcb4b7299adcb38eb2d290bac8b048efaebac62be0837e1f307d692ef2e02452f07ea234e30b8ec89db44d1e9a7972ebd0d741ffe24b5c1fac3adb73d7176c }


condition:
	$a0
}