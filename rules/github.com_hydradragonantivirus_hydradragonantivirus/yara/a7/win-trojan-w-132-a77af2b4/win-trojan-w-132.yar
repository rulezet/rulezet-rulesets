rule Win_Trojan_W_132
{
strings:
	$a0 = { 526164697831365dbe3c00f7bfad050000f7bf968b76788db61c00f7bfad8b800000f7bf05 }


condition:
	$a0
}