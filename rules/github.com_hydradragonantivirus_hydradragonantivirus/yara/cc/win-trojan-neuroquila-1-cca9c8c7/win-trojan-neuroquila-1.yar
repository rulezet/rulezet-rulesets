rule Win_Trojan_Neuroquila_1
{
strings:
	$a0 = { fac7c6????c7c1????8bc08cc88ed8fd290c988db402009889f03d????fd7303fbebed }


condition:
	$a0
}