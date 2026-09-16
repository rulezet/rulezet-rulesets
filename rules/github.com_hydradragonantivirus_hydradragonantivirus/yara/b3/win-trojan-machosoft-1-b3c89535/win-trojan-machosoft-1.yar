rule Win_Trojan_MachoSoft_1
{
strings:
	$a0 = { 56be5900b9260890d1e98ae18ac1 }


condition:
	$a0
}