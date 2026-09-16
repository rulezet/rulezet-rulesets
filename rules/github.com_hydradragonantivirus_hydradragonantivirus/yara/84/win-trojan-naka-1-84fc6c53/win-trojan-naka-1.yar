rule Win_Trojan_Naka_1
{
strings:
	$a0 = { 9c015944745bb8024233c933d2cd215250b440b9fd018bd6cd21b8024233c933d2cd21b90002 }


condition:
	$a0
}