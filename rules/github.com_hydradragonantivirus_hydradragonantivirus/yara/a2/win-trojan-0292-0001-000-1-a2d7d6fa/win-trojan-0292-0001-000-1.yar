rule Win_Trojan__0292_0001_000_1
{
strings:
	$a0 = { cd21b4402e8b1e1d01b9cc01ba0001cd21b800422e8b1e1d0133c933d2cd212ea11f012d03 }


condition:
	$a0
}