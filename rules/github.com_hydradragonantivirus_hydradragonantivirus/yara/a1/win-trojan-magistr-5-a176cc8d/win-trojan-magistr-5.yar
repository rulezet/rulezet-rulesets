rule Win_Trojan_Magistr_5
{
strings:
	$a0 = { 67a1000083ec0489042433c0648920 }


condition:
	$a0
}