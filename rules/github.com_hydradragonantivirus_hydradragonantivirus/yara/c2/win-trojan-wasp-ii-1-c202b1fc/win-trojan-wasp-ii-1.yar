rule Win_Trojan_Wasp_II_1
{
strings:
	$a0 = { 2005ba0001cd217310e86b02e87102b441baeb04cd }


condition:
	$a0
}