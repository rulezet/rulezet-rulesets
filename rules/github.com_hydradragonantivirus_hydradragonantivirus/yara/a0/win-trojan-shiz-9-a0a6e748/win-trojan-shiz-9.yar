rule Win_Trojan_Shiz_9
{
strings:
	$a0 = { 453a5c71685c727a6f3435326b705c62725c67727762656764665c7a78706d2e706462 }


condition:
	$a0
}