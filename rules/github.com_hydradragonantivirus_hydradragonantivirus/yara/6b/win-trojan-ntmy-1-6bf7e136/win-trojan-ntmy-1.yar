rule Win_Trojan_NTMY_1
{
strings:
	$a0 = { 8bfb59fcf3a4b80403bb0001b90200ba8000cd13720eb80103bb000ab90100ba8000cd13c3 }


condition:
	$a0
}