rule Win_Trojan_SillyC_137
{
strings:
	$a0 = { 81ed0c01bf00018db6f201a5a5b41a8d960002cd21e81a00b41aba8000cd21b800015033c033db33c933d233f633ff }


condition:
	$a0
}