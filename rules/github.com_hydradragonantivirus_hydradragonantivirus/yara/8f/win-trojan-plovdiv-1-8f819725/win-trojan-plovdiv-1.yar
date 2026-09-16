rule Win_Trojan_Plovdiv_1
{
strings:
	$a0 = { 816f1d2003079d5a5beb02cd32559c }


condition:
	$a0
}