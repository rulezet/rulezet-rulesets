rule Win_Trojan_Leprosy_10
{
strings:
	$a0 = { 3390e8040090e9f400905190bb3d018a2f90322e0301882f43 }


condition:
	$a0
}