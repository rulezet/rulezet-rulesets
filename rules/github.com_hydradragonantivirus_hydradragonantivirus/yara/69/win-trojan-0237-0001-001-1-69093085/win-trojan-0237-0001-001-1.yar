rule Win_Trojan__0237_0001_001_1
{
strings:
	$a0 = { b8004233c999cd21b4408d96bb0259cd21fe8eba02e937ffb801438d96ad02cd21c35db440 }


condition:
	$a0
}