rule Win_Trojan_Trivial_319
{
strings:
	$a0 = { 3501b484b44ecd21baab00ba9e00b447b43c80c1b080e9b0cd21e90000ba0001b738b740b13981f2d70081f2d70093e90000cd212a2e2a00 }


condition:
	$a0
}