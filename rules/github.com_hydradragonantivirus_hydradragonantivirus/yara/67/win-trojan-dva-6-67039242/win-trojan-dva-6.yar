rule Win_Trojan_DVA_6
{
strings:
	$a0 = { 8bf281ee0301c35ee98100b42fcd218c841d04899c1f0433d28bd681c2f10281c200100e1fb41acd2189941b04c3 }


condition:
	$a0
}