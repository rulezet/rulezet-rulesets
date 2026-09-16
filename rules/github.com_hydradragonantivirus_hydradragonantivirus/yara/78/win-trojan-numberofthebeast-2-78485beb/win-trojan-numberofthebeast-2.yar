rule Win_Trojan_NumberoftheBeast_2
{
strings:
	$a0 = { 0e1f1e0706b05050b43fcbcd2172 }


condition:
	$a0
}