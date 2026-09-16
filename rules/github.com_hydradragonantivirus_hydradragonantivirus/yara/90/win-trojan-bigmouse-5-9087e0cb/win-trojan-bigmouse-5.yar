rule Win_Trojan_BigMouse_5
{
strings:
	$a0 = { cd213d11237502eb541f8cc28bda4b8edb33ff803d5a75458b45032d4500894503836d124503c28ec0fc0e1fe8c6 }


condition:
	$a0
}