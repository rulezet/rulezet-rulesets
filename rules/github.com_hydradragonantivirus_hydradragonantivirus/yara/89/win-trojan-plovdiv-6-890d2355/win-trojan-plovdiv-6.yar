rule Win_Trojan_Plovdiv_6
{
strings:
	$a0 = { e21f80fa1e750626816f1d2003079d5a5beb02cd32559c }


condition:
	$a0
}