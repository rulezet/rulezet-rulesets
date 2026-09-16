rule Win_Trojan_Sality_1029
{
strings:
	$a0 = { 60e8270000000c302112ea857bf947e2d4518d66093451d9d9df1bee72d8bf76a1bf11 }


condition:
	$a0
}