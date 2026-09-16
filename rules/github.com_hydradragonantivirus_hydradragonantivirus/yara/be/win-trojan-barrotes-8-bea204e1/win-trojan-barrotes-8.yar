rule Win_Trojan_Barrotes_8
{
strings:
	$a0 = { 8d165a01b440cd217210e86801720bb952078d160001b440cd212e8b1e52012e8b164a012e }


condition:
	$a0
}