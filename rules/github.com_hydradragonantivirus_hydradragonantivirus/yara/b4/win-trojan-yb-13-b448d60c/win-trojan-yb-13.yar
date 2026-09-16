rule Win_Trojan_YB_13
{
strings:
	$a0 = { 3d9cff9c680172e393b905008d945f01b43f9cff9c68 }


condition:
	$a0
}