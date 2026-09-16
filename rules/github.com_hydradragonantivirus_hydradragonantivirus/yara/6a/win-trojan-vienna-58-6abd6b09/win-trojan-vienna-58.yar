rule Win_Trojan_Vienna_58
{
strings:
	$a0 = { 018c440307ba600001f2b41acd2106568e062c00bf00 }


condition:
	$a0
}