rule Win_Trojan_Vienna_68
{
strings:
	$a0 = { 90cd211f5933c033db33d233f6bf00015733ffc2ffff }


condition:
	$a0
}