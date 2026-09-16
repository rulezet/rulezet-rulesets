rule Win_Trojan_Face_3
{
strings:
	$a0 = { 582d0300b104d3e88ccb03c38ed8a11d0b8cc303c305100050ff361b0b0606fcb8fe4bcd213d44447503e9a700b007e6 }


condition:
	$a0
}