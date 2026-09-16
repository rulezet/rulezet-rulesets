rule Win_Trojan_Ghost_2_2
{
strings:
	$a0 = { f44ed5f0497bf239e4a940f439e786f240fc467439e787f71d87f5faf3eaf37cc231f17e35d0cb56 }


condition:
	$a0
}