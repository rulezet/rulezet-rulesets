rule Win_Trojan_CPXK_1
{
strings:
	$a0 = { b43ecd21e95fff8b443287443a8944328b443487443c89 }


condition:
	$a0
}