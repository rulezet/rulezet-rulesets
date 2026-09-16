rule Win_Trojan_Companion_13
{
strings:
	$a0 = { cd218bd8ba0001b1dbb440cd21b43ecd21eb13b4 }


condition:
	$a0
}