rule Win_Trojan_Crypted_2
{
strings:
	$a0 = { 68??????00e8??????00 }

	$a1 = { 68000000008b74242c89e581ecc000000089e70375008a06[0-8]0fb6c0 }


condition:
	$a0 and $a1
}