rule Win_Trojan_Skew_4
{
strings:
	$a0 = { 0f008d139102061eb800008ec00e1fbe0001bf000226803e0002eb742e26803e0002e97426b9d501fc }


condition:
	$a0
}