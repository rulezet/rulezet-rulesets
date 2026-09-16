rule Win_Trojan_Slam_4
{
strings:
	$a0 = { a00a013c00740c6630074302c781fb2f027ef4c3 }


condition:
	$a0
}