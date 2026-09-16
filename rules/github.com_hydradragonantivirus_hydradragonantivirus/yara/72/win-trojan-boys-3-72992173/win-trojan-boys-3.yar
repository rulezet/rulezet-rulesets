rule Win_Trojan_Boys_3
{
strings:
	$a0 = { 01ad050300508bf0bf0001b90500 }


condition:
	$a0
}