rule Win_Trojan_Murphy_17
{
strings:
	$a0 = { 2e8b842cfb2ea300012e8b842efb2ea3 }


condition:
	$a0
}