rule Win_Trojan_Tiny_21
{
strings:
	$a0 = { b43f061fba4f015459cd21803e4f01927413054f005033c9f7e1b442cd2159b440fec6cd21 }


condition:
	$a0
}