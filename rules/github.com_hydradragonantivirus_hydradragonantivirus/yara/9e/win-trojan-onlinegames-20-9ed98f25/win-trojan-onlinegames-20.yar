rule Win_Trojan_Onlinegames_20
{
strings:
	$a0 = { 5383f0a45223c4e80200000023c233c45bbab56d70ef3d2d52 }


condition:
	$a0
}