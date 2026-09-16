rule Win_Trojan_Virut_202
{
strings:
	$a0 = { e8??000000 }

	$a1 = { 558b6c2404816c2404????????e8??ffffff8bc8e8??ffffff2bc13d00010000734b0f00c167e3d18b5c240881e300f0ffff81ed051040008b0b86e96681f95a4d740881c300f0ffffebed }


condition:
	$a0 and $a1
}