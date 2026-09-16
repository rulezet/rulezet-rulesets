rule Win_Trojan_Newboot_1
{
strings:
	$a0 = { 8ec0b90001fcf3a5cd19b922008bd9309f497ce2f8c380fcaa7501cf3d01027403e9810083 }


condition:
	$a0
}