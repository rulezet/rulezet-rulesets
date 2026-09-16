rule Win_Trojan_W95_5
{
strings:
	$a0 = { 50b43ecd21bb1160ba1200e83e0059b440e83300b43ecd21bce903b33fb44acd21bbcb }


condition:
	$a0
}