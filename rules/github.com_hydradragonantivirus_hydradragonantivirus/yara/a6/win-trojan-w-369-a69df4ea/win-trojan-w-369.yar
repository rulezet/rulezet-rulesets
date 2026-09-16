rule Win_Trojan_W_369
{
strings:
	$a0 = { 0301b91201b440ba000103d5cd21ccb8004233c933d2cd21b440b90300ba020103d5cd21b8 }


condition:
	$a0
}