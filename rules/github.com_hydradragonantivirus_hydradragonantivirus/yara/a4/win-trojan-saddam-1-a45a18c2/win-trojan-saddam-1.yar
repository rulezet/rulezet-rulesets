rule Win_Trojan_Saddam_1
{
strings:
	$a0 = { 8bc8a186001f39c8744151b9cc02be }


condition:
	$a0
}