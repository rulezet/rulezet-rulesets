rule Win_Trojan_DSCE_2
{
strings:
	$a0 = { 470fd9769a3578e396b8bb7a53bf3771b879ebd3a1bb70b5a40366f0769a86f066cf9637bdf9ba37bdfdba37bdf1ba00 }


condition:
	$a0
}