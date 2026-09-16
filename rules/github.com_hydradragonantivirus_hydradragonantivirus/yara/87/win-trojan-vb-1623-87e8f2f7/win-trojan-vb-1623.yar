rule Win_Trojan_VB_1623
{
strings:
	$a0 = { 72736f7279206f776c6973686e65737300325c0074646f }


condition:
	$a0
}