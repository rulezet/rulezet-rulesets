rule Win_Trojan_Fisher_2
{
strings:
	$a0 = { 80fc56742c80fc41742a3d02cc7403eb0590b8cc4bcf }


condition:
	$a0
}