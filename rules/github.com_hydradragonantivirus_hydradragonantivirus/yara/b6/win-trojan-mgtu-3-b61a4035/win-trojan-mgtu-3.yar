rule Win_Trojan_MGTU_3
{
strings:
	$a0 = { 8d0e0d028d1600012bca8bd581c20001cd21b440b904008d160901 }


condition:
	$a0
}