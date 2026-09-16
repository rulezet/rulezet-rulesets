rule Win_Spyware_5159_1
{
strings:
	$a0 = { 60e8060000008b642408eb0c??d264ff32648922cc02ebe8[0-20]8b1c245881eb }


condition:
	$a0
}