rule Win_Trojan_Azusa_3
{
strings:
	$a0 = { 0e1802f6f1d1f8fec888c5b601890e8d00b80103e81c00720db8010331dbb90100b600e80d005f }


condition:
	$a0
}