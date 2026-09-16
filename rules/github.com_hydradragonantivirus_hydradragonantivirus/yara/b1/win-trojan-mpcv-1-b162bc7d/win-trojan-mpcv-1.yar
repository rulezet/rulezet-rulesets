rule Win_Trojan_MPCV_1
{
strings:
	$a0 = { 961a0259cd21b8024233c999cd21b4408d960301b9ec00cd21b801578b8e05028b960702cd }


condition:
	$a0
}