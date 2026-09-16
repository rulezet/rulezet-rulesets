rule Win_Trojan_Peed_390
{
strings:
	$a0 = { 6a006a014889c583ed0283ed036609edf2740505 }


condition:
	$a0
}