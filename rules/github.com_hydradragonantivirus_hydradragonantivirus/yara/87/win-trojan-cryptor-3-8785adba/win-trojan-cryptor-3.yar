rule Win_Trojan_Cryptor_3
{
strings:
	$a0 = { 320de80b00eb0eb44233c933d2cd21c3b440cd21c3b801572e8b8e200d2e8b96220dcd21b43e }


condition:
	$a0
}