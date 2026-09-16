rule Win_Trojan_Small_4461
{
strings:
	$a0 = { 83ec04b8??????fff7d089e28902ba????ff0052 }


condition:
	$a0
}