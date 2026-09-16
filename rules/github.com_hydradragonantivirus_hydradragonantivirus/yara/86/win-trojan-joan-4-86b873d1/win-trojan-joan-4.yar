rule Win_Trojan_Joan_4
{
strings:
	$a0 = { 56571e06e800005e83ee0a0e1f33ff8b84f9018945068b84fb018945108ec726803efa04ea745eb8fa04268706 }


condition:
	$a0
}