rule Win_Trojan_Small_4421
{
strings:
	$a0 = { 81c8????40005050684cba4af4e85b000000e87000000068 }


condition:
	$a0
}