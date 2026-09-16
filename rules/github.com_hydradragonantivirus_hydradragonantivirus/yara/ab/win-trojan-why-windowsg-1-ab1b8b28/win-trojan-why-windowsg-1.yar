rule Win_Trojan_Why_WindowsG_1
{
strings:
	$a0 = { bb01018a27bb02018a0786c40503008bf0b41a8d94c8 }


condition:
	$a0
}