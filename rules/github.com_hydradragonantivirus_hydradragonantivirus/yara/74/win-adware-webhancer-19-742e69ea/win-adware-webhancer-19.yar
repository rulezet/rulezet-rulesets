rule Win_Adware_Webhancer_19
{
strings:
	$a0 = { 505f53484f52545f4e414d45000077656248616e63657220496e7374616c }


condition:
	$a0
}