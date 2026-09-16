rule Win_Trojan_Cryptor_2
{
strings:
	$a0 = { 0ce80b00eb0eb44233c933d2cd21c3b440cd21c3b801572e8b8eab0c2e8b96ad0ccd21b43e }


condition:
	$a0
}