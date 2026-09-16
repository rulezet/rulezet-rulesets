rule Win_Trojan_Baobab_1
{
strings:
	$a0 = { c08ed8813fff107425c707ff101ffcf3a42e8b1ed5028e }


condition:
	$a0
}