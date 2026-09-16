rule Win_Trojan_Bowl_3
{
strings:
	$a0 = { 0332c0e8ddffb90300b440ba280301eacd21b002e8ccffb92602b440ba090101eacd2172ad }


condition:
	$a0
}