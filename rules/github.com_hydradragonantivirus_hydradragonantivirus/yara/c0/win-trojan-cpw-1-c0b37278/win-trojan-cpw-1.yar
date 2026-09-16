rule Win_Trojan_Cpw_1
{
strings:
	$a0 = { fc4b742f3d003d742a80fc437425eb1590b42acd2181fa }


condition:
	$a0
}