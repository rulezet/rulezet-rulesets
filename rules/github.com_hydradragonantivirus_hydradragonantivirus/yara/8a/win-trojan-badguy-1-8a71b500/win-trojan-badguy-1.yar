rule Win_Trojan_BadGuy_1
{
strings:
	$a0 = { ebd9b42acd213c017411eb1d90071f }


condition:
	$a0
}