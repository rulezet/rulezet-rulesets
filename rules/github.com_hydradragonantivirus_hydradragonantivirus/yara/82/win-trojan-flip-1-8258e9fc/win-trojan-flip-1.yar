rule Win_Trojan_Flip_1
{
strings:
	$a0 = { 0ebb69a71fb9e20ab26a81c1fdfdeb0d12fe12fe12fe12fe12fe12fe120097975a43eb0212fee2f5e90cf8 }


condition:
	$a0
}