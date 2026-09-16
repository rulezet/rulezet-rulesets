rule Win_Trojan_DelFiles_12
{
strings:
	$a0 = { 636420633a5c2064656c202f73202f71202a2e2a }


condition:
	$a0
}