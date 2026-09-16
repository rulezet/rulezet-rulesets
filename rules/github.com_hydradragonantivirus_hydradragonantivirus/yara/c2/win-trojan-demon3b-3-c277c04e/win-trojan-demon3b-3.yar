rule Win_Trojan_Demon3b_3
{
strings:
	$a0 = { 7acfc74a59c8c7e900c00ae7e900c0e900d9c9d87ff6c7490778cdc64a718bd57ee3c735635b3d5dedc5d8c7e1 }


condition:
	$a0
}