rule Win_Trojan_Tequila_6
{
strings:
	$a0 = { 060089c7be190a84f2b9cc0939e880c13285fc8a1484fe301746439081fe440a720539ecbe040a39dd85c1e2e6e919f8a62ea62ea62e }


condition:
	$a0
}