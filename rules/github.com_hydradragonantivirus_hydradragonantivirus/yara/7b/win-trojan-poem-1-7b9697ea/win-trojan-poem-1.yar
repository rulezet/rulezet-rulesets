rule Win_Trojan_Poem_1
{
strings:
	$a0 = { 83ee03508bfe83c731908b441ce8d606 }


condition:
	$a0
}