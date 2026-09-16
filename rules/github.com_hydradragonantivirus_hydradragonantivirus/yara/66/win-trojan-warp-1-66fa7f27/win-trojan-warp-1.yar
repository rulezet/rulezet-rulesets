rule Win_Trojan_Warp_1
{
strings:
	$a0 = { 41577504b85052cf80fc4b7527505351521eb8014333c9 }


condition:
	$a0
}