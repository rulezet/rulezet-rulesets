rule Win_Trojan_Osiris_1
{
strings:
	$a0 = { be00008a94ef0180f2c646b402cd21e2f2b44e33c9 }


condition:
	$a0
}