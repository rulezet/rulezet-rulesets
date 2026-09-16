rule Win_Trojan_Vienna_24
{
strings:
	$a0 = { 0277125933c033d233f633dbbf00015733ffc2fffff4 }


condition:
	$a0
}