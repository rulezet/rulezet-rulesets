rule Win_Trojan_Exchanger_5
{
strings:
	$a0 = { e81c000000e8e6ffffff81c3[4]e8dbffffffe846ffffffe2e4 }


condition:
	$a0
}