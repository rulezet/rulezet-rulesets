rule Win_Trojan_Nazi_10
{
strings:
	$a0 = { dfdb0920202020db202020db09dfdfdfdfdf202020df5589e5bf96451e57bffd0d0e576a009a70 }


condition:
	$a0
}