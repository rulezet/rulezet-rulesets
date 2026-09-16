rule Win_Trojan_KillMBR_5
{
strings:
	$a0 = { bf0002b90001b80000f2abb80103bb0002b90100ba8000cd13b8004ccd21c3 }


condition:
	$a0
}