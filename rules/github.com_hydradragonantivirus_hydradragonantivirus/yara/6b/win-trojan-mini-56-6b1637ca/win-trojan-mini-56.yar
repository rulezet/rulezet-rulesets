rule Win_Trojan_Mini_56
{
strings:
	$a0 = { 9e00cd2193b43f54598d12cd213e803a2a741203c55033c9f7e1b442cd2189f259b440cd21b44f }


condition:
	$a0
}