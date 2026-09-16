rule Win_Trojan_ES_1
{
strings:
	$a0 = { 296e0e66c05c2bc3f4f211e4f7c329918611365e5369bacc53ed3f9125ec7ca59bb27d884c15de342024 }


condition:
	$a0
}