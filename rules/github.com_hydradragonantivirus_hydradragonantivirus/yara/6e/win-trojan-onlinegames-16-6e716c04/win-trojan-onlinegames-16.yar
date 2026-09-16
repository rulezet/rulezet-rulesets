rule Win_Trojan_Onlinegames_16
{
strings:
	$a0 = { 537465616d2070617373776f7264206465636f646572 }

	$a1 = { 2e626c6f622f70617373776f72645d }


condition:
	$a0 and $a1
}