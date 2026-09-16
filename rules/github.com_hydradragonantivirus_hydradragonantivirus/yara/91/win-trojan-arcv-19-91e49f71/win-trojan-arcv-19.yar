rule Win_Trojan_ARCV_19
{
strings:
	$a0 = { fafebd11012e817600000045454275f5 }


condition:
	$a0
}