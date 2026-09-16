rule Win_Trojan_Loren_1
{
strings:
	$a0 = { 2e8b86d0052e8986db0558c3e800005d81ed4905e89400 }


condition:
	$a0
}