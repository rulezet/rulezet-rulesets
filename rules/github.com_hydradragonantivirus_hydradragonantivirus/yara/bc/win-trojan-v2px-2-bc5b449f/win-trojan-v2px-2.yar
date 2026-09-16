rule Win_Trojan_V2PX_2
{
strings:
	$a0 = { d990310d43474b42f8904640e2eb }


condition:
	$a0
}