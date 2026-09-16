rule Win_Trojan_Packed_33
{
strings:
	$a0 = { 60e8060000008b642408eb0c[0-20]e800000000????8b1c245881eb }


condition:
	$a0
}