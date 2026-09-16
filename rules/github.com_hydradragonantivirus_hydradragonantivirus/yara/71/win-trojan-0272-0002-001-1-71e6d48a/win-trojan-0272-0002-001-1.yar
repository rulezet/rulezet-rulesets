rule Win_Trojan__0272_0002_001_1
{
strings:
	$a0 = { e88c00b002e87d00b4408d96750359cd21b8024233c999cd21b42ccd210bd274f889960a01 }


condition:
	$a0
}