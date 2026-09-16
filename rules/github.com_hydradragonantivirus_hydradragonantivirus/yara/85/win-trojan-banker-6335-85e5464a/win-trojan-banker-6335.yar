rule Win_Trojan_Banker_6335
{
strings:
	$a0 = { 6e6e74703a2f2f00ffffffff0900000074656c6e65743a2f2f }

	$a1 = { 5c66696e646e65772e747874[0-12]5c6361646f6b2e747874 }


condition:
	$a0 and $a1
}