rule Win_Trojan_SOTL_1
{
strings:
	$a0 = { 80fc2d750d80fdff750838f57504b0009dcffc50 }


condition:
	$a0
}