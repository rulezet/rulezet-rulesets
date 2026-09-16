rule Win_Trojan_Ugly_2
{
strings:
	$a0 = { d41deea0fe922e5297a92f9536527f2031ae192e6d675bd7 }


condition:
	$a0
}