rule Win_Trojan_Rael_1
{
strings:
	$a0 = { ffbb9a0188ff0e1f88ff8b0788f63306050188f6890788ff4388f681fb7b0d740b88ff4388f6 }


condition:
	$a0
}