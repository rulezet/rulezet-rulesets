rule Win_Trojan_Tony_6
{
strings:
	$a0 = { 0312cd2f33f6ad3d2e3a74064e75f7e9 }


condition:
	$a0
}