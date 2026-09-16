rule Win_Trojan_Small_186
{
strings:
	$a0 = { 50b02b90b3438ec0b1419090f3a41f87013c2b90907406ab8cc08701ab0e070e1f5f2bcef3a4ebd5608bf2ac3de940750b1e0e1f99b9410090cd211f61ea }


condition:
	$a0
}