rule Win_Trojan_Peed_352
{
strings:
	$a0 = { 81fbf05500007f43b951ca25ff4881c1ff45da00ba80080800c1 }


condition:
	$a0
}