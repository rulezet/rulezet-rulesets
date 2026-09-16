rule Win_Trojan_DarkAvenger_1
{
strings:
	$a0 = { 2658595b58807f0a0075088b57085b53cd26585e33c08e }


condition:
	$a0
}