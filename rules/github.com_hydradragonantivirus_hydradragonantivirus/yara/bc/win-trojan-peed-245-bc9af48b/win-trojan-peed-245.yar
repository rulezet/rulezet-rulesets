rule Win_Trojan_Peed_245
{
strings:
	$a0 = { b85468220087fb73118f0563364202ff1584464705ff10f7d85bb9d0 }


condition:
	$a0
}