rule Win_Trojan_Stoned_15
{
strings:
	$a0 = { be0b02bf0b00fcf3a4b13cbe8201bf8203f3a7749abf0103e8190072928bc7 }


condition:
	$a0
}