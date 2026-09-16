rule Win_Trojan_Stack_2
{
strings:
	$a0 = { 213d34127502cd208cc0a3f6018ed8e84900e87c000e0e1f07a1f601b104d3e08b1ef80183e3f003c3b104d3e8 }


condition:
	$a0
}