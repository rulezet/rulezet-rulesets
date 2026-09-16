rule Win_Trojan_B_84
{
strings:
	$a0 = { dbfabc007c8ed3fb8edb832e130404 }


condition:
	$a0
}