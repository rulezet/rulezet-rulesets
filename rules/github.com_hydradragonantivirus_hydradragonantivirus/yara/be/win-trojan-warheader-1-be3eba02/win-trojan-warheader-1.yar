rule Win_Trojan_WarHeader_1
{
strings:
	$a0 = { 57bf6c070e5731c0509ad30845019a400845019af4044501eb5abf2b031e57bf2b031e57 }


condition:
	$a0
}