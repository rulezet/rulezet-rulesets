rule Win_Trojan_Dreg_5
{
strings:
	$a0 = { 9ce08cd933c0eb0552baab545a8ed88b166c048ed949415f5257f6d50d0000f6d5c380ef5580 }


condition:
	$a0
}