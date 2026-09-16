rule Win_Trojan_Enmity_3
{
strings:
	$a0 = { e80000589181e9080187e9e8fe02eb05b8004ccd2150558becc74602011a5d50558becc7460200015d8db605045f }


condition:
	$a0
}