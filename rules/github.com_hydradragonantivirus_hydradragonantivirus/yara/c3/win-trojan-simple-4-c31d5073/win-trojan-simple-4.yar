rule Win_Trojan_Simple_4
{
strings:
	$a0 = { 12018bfeb1bdac3400aafec980f9ff75f5 }


condition:
	$a0
}