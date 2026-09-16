rule Win_Trojan_Yankee_9
{
strings:
	$a0 = { e800005fb3ea81ef9c09b71b1eb7250e1fb3308a25b72683c729b96f09b7053025b75a47b3e5e2f7 }


condition:
	$a0
}