rule Win_Trojan_UVR_1
{
strings:
	$a0 = { 1001f2cd21b8004231d231c9cd21b440b90c00bac10201f2cd21b44059ba541001f2cd21b43e }


condition:
	$a0
}