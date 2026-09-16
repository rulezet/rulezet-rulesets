rule Win_Trojan_USSR_26
{
strings:
	$a0 = { 8a6521882600018b4522a301018b }


condition:
	$a0
}