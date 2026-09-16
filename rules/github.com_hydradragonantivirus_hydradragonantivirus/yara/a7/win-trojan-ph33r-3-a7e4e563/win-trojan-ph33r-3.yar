rule Win_Trojan_Ph33r_3
{
strings:
	$a0 = { ffffcd213dcccc7416b802faba455932dbcd168cd8488ed833ff803d597701c3816d034900816d1249008b451206 }


condition:
	$a0
}