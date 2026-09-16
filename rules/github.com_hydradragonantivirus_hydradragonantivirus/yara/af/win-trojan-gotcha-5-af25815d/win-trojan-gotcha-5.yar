rule Win_Trojan_Gotcha_5
{
strings:
	$a0 = { bf00012e8a2c2e882d2e8a6c012e886d012e8a6c022e886d0257501e0656b8cccccd213dbbbb74375e5681ee }


condition:
	$a0
}