rule Win_Trojan_Istanbul_1
{
strings:
	$a0 = { 7504b83434cf3d004b7402eb6e515657065053521e }


condition:
	$a0
}