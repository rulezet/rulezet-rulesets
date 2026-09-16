rule Win_Trojan_K_37
{
strings:
	$a0 = { b44acd212ea12c00a344018c0e48018c0e4c018c0e5001e87b00c6060c0100be0c01bf0d01b92b00fcf3a4b41a }


condition:
	$a0
}