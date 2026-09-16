rule Win_Trojan_Pleo_1
{
strings:
	$a0 = { 45786563757465282244696d20 }

	$a1 = { 203d20417363284d696428 }

	$a2 = { 20586f7220[0-3]29222b766263726c662b226e6578743a }


condition:
	$a0 and $a1 and $a2
}