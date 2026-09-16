rule Win_Trojan_Ply_2
{
strings:
	$a0 = { cd2190b43e90cd2190b86d7a2d202039049074139086e090390490740a90b8206f2d2020eb }


condition:
	$a0
}