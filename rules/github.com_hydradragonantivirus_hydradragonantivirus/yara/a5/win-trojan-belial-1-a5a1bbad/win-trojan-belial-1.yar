rule Win_Trojan_Belial_1
{
strings:
	$a0 = { e800005d81ed030183fd00743a8db64701b986022e802c0183c601e2f75b83fb01745d53eb2190b9 }


condition:
	$a0
}