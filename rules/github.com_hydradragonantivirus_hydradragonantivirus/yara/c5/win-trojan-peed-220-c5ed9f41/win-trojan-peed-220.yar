rule Win_Trojan_Peed_220
{
strings:
	$a0 = { 93b8262503007333445aff15ffff0000ff135589e551418b7d0c66abc1c80390 }


condition:
	$a0
}