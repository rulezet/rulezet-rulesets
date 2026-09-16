rule Win_Trojan_Trojan_311
{
strings:
	$a0 = { c0be007c8be68ed0fb8ed88ec0cd1a32f280e63f7520b280b90f00bb00308ec333dbb80202cd137308 }


condition:
	$a0
}