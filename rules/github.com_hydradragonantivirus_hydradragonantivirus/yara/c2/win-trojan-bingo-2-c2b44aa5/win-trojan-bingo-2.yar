rule Win_Trojan_Bingo_2
{
strings:
	$a0 = { bb4d69cd2181fa47627454e8f4000e07b44a33db4bcd21b44a83eb1590cd21b448bb140090cd218ec0488ed8c6 }


condition:
	$a0
}