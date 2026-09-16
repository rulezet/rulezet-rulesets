rule Win_Trojan_DarkAvenger_2
{
strings:
	$a0 = { 088b57085b53cd26585e33c08ed82e }


condition:
	$a0
}