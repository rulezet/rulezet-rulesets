rule Win_Trojan_Rape_6
{
strings:
	$a0 = { e800005e81ee9a098bfe57501e060e1f0e07b633b99709ac5188f1d2c8fec659aae2f4 }


condition:
	$a0
}