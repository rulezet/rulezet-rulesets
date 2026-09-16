rule Win_Trojan_Onlinegames_18849
{
strings:
	$a0 = { ccebebe8000005140000776f776d6d000000ffffffff04000000776f775c00000000ffffffff0b00000073766f686373742e6578 }


condition:
	$a0
}