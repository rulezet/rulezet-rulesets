rule Win_Trojan_Peed_286
{
strings:
	$a0 = { 50e89e00000051b9e803000089d781c12823000066abc1c80ac1c806aa86c4aa }


condition:
	$a0
}