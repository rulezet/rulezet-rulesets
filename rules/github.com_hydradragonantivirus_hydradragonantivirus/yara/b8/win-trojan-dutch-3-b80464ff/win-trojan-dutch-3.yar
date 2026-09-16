rule Win_Trojan_Dutch_3
{
strings:
	$a0 = { cd21803c4d7428b002e82b0097b175b440cd21b000 }


condition:
	$a0
}