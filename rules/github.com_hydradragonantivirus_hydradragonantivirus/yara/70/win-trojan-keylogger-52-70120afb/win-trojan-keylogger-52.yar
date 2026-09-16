rule Win_Trojan_Keylogger_52
{
strings:
	$a0 = { 83c30481fbf82740000f8c7affffffff45ec83c6048b45ec3b45dc0f8e63ffffff834dfcff8d4dd4e8b4efffff8b4df45f5e33c05b64890d00000000c9c3 }


condition:
	$a0
}