rule Win_Trojan_Vengence_5
{
strings:
	$a0 = { ba2d01b44ecd217222ba9e00b8023dcd2172189353b1c283 }


condition:
	$a0
}