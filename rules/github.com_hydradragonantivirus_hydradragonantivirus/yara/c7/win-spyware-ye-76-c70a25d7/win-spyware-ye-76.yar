rule Win_Spyware_ye_76
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]499753a06403b6e0822f52446c09b9 }


condition:
	$a0
}