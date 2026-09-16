rule Win_Trojan_Vienna_66
{
strings:
	$a0 = { 8b9410008e9c1200cd211f5933c033db33d233f6bf }


condition:
	$a0
}