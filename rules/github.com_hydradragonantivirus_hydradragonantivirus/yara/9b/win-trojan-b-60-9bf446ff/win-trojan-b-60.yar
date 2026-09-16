rule Win_Trojan_B_60
{
strings:
	$a0 = { 1332f6b101b801032e88160efc83f901750b80fc02750681fa80007604cdcdeb6fcdcd726b601e }


condition:
	$a0
}