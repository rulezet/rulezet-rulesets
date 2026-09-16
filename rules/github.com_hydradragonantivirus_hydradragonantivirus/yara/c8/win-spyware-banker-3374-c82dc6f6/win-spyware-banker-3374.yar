rule Win_Spyware_Banker_3374
{
strings:
	$a0 = { 3d7479300ba7ab2e06cadc69a1cf8435691b087c935326e4b66a3a89ed8c47177e7d6d61037e739b72ff8a309db7b508bd53fbbf39fe6e8dd1234f063f2cbaebdb298f5f2603 }


condition:
	$a0
}