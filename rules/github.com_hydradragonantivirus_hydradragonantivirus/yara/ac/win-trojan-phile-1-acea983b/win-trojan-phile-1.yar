rule Win_Trojan_Phile_1
{
strings:
	$a0 = { 52b440b9d100ba0001cd21b801575a59cd21b8014359ba }


condition:
	$a0
}