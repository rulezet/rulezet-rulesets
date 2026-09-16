rule Win_Trojan_Lucky_8
{
strings:
	$a0 = { e800005d8bf581c6????bf0001fca5a5b44eb90f00bafb0190cd217207 }


condition:
	$a0
}