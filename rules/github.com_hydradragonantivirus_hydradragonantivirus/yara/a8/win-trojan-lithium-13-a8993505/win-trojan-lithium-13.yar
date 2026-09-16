rule Win_Trojan_Lithium_13
{
strings:
	$a0 = { f88b15fc954100e86e79feff8d45fce86e78feffc3e92878feffebcd5f5e5b8be55dc300000001000000ffffffff09000000254c69746869756d5c000000ffffffff010000005c }


condition:
	$a0
}