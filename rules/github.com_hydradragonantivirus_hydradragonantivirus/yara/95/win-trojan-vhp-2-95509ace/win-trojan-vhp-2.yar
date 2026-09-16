rule Win_Trojan_VHP_2
{
strings:
	$a0 = { be7f0a8bd683c600fcb90300bf0001f3 }


condition:
	$a0
}