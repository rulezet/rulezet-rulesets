rule Win_Trojan_Milan_4
{
strings:
	$a0 = { 01b93a012e8a1780f2492e881743e2f4eb0190 }


condition:
	$a0
}