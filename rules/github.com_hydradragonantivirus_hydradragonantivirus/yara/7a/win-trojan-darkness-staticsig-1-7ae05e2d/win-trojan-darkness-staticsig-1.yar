rule Win_Trojan_Darkness_staticsig_1
{
strings:
	$a0 = { 4d219722e5729e2fdce0457c40f60ce97b65addd31a38baeb6b8 }


condition:
	$a0
}