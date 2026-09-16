rule Win_Trojan_Pascal_2
{
strings:
	$a0 = { e800005e81ee6b01888454018b8406 }


condition:
	$a0
}