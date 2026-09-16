rule Win_Trojan_U_8
{
strings:
	$a0 = { 35d0c50a088d45f85068cf6c0908e8ac55000083c41083ec0c68d76c0908e844f9ffff83c410c9c35589e583ec0883ec0cb8ffefffff2b05e8ec8a08c1e80c }


condition:
	$a0
}