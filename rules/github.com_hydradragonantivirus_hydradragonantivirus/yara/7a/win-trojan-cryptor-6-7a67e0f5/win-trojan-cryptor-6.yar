rule Win_Trojan_Cryptor_6
{
strings:
	$a0 = { 967812e80b00eb0eb44233c933d2cd21c3b440cd21c3b801572e8b8e64122e8b966612cd21b43e }


condition:
	$a0
}