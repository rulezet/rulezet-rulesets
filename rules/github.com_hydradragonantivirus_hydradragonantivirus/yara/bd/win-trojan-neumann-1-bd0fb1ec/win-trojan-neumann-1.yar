rule Win_Trojan_Neumann_1
{
strings:
	$a0 = { 0e1fba6001cd212e803e560100743733dbeb0e2e8b }


condition:
	$a0
}