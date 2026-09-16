rule Win_Trojan_Agent_31365
{
strings:
	$a0 = { 747470f65d7bbbb22f77002e62650b2f65617263680c6d01daf6697a2fa2736d4b2e241facfebf6d2b5c74766d6b31 }


condition:
	$a0
}