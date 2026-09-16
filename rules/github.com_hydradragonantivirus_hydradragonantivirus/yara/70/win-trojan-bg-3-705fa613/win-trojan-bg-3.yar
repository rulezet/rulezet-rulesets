rule Win_Trojan_Bg_3
{
strings:
	$a0 = { 6081c217008edabb1b008007[1-6]83c30181fb570876ef }


condition:
	$a0
}