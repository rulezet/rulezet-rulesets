rule Win_Trojan_DirII_4
{
strings:
	$a0 = { a469a22044874a2ff079eb8bf2b3886c50d251fc886c5070 }


condition:
	$a0
}