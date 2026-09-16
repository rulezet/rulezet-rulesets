rule Win_Trojan_Clouds_1
{
strings:
	$a0 = { 90e800005d81ed0701603e8b9e05032e891e00013e8b9e07032e891e02018dbe2d010e1f0e06b8ffffaa90903e }


condition:
	$a0
}