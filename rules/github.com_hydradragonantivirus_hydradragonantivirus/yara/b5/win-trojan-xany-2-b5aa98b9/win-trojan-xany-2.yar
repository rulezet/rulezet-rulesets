rule Win_Trojan_Xany_2
{
strings:
	$a0 = { 5450b4408bd683ea0bb93e01cd215872442d0300538bde83eb0b2e894701c607e95bb80042 }


condition:
	$a0
}