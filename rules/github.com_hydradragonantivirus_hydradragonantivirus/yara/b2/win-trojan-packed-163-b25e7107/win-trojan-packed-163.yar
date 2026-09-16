rule Win_Trojan_Packed_163
{
strings:
	$a0 = { 5783ec7c545f6a7c57e8????0000??????5703f8b85c6d6369abb877617665abb82e646c6cab33c0abe8????000083c4 }


condition:
	$a0
}