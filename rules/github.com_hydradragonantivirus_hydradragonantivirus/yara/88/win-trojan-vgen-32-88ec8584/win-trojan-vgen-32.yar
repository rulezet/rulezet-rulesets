rule Win_Trojan_VGEN_32
{
strings:
	$a0 = { 0dcd2133ff8edfb7024fb8024acd2fbb060047742ce8d4fff32ea4b85e028747fe50ff378c0f87cfb2819c9c9c5880 }


condition:
	$a0
}