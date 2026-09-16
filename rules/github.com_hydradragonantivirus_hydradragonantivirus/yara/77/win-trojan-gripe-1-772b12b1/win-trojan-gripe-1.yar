rule Win_Trojan_Gripe_1
{
strings:
	$a0 = { 8d603332147e3060ccf04e2b3716b8fd8dfcca301b39cc9c350be439339ccad108ff818b27c25506 }


condition:
	$a0
}