rule anti_debug__Softice_NmSymIsSoftICELoaded__8_byt_STR_21_
{
strings:
	$a0 = { 4e6d53796d4973536f66744943454c6f6164656400 }

condition:
	$a0
}