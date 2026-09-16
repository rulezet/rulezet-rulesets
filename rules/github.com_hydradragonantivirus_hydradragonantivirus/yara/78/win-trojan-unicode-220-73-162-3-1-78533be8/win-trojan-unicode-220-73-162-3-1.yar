rule Win_Trojan_Unicode_220_73_162_3_1
{
strings:
	$a0 = { 3200320030002e00370033002e003100360032002e0033 }


condition:
	$a0
}