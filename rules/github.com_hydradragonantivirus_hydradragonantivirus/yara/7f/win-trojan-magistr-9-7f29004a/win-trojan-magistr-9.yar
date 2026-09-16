rule Win_Trojan_Magistr_9
{
strings:
	$a0 = { c064ff30646789260000 }


condition:
	$a0
}