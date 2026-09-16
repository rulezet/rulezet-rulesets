rule Win_Trojan_Peed_157
{
strings:
	$a0 = { f7db87da755489daf7da01d0baaaffffff83f8007479c368b5f5fcff56e82c0000002d }


condition:
	$a0
}