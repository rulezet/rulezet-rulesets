rule Win_Trojan_Xam_1
{
strings:
	$a0 = { fcb07504b8fcdecf505351525657061e558ac43c4b7465 }


condition:
	$a0
}