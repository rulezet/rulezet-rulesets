rule Win_Trojan_Pleo_2
{
strings:
	$a0 = { 457865637574652822 }

	$a1 = { 3d417363284d696428 }

	$a2 = { 20586f7220[0-3]29222b766263726c662b226e6578743a }


condition:
	$a0 and $a1 and $a2
}