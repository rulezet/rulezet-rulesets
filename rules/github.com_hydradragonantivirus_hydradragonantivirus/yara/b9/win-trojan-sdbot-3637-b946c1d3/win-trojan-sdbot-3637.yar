rule Win_Trojan_SdBot_3637
{
strings:
	$a0 = { 02fd0e4511b60fc5d54f88bdb224ff2d3991d0ae54838fedc6b58cf69e83e7df14f7f0f6cd5982db3ee784886799a5ca8a587aae216904c3cde6b920a79c95ff55bb98f3fff6afd708ed2c10740b }


condition:
	$a0
}