rule Win_Trojan_Vengeance_1
{
strings:
	$a0 = { cd21b402b207cd21ebf85933c033db33d233f6bf00 }


condition:
	$a0
}