rule Win_Trojan_Hupigon_700
{
strings:
	$a0 = { ff8f2fa52571ae9c289018c77aab4f05bf2268be8135f7a462279962118029bdb011fc762d60836e77d2437a2e86eb02c926f24a36abd3f4832b6db9 }


condition:
	$a0
}