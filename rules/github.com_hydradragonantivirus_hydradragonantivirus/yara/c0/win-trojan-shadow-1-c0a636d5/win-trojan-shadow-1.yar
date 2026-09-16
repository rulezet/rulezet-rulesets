rule Win_Trojan_Shadow_1
{
strings:
	$a0 = { e800005e83ee0cbb????8b54278b0033c2890083c30281fb8f047cf1eb02 }


condition:
	$a0
}