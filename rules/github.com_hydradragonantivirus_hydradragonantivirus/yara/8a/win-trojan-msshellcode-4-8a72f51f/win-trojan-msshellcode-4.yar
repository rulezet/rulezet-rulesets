rule Win_Trojan_MSShellcode_4
{
strings:
	$a0 = { eb5a31c08b348301d6535031db31c0acc1c30501c383f80075f3c1cb0539cb585b740340ebdec389d08b403c8b4402788d0402508b40208d1c02e8c3ffffff5b }


condition:
	$a0
}