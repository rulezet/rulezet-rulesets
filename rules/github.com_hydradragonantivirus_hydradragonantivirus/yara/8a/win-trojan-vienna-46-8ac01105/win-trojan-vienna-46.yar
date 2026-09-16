rule Win_Trojan_Vienna_46
{
strings:
	$a0 = { b41a8b1490908e5c0290cd211f5933c033db33d233f6bf00015733ffc2ffff }


condition:
	$a0
}