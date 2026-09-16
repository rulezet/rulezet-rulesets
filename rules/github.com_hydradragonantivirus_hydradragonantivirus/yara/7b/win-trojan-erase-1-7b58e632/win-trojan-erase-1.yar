rule Win_Trojan_Erase_1
{
strings:
	$a0 = { ffb41acd218b2e3f01ba2603b82425cd21b42acd2180fa0b741280fa17740de80502f8a0fafb3c0b7433eb13e900 }


condition:
	$a0
}