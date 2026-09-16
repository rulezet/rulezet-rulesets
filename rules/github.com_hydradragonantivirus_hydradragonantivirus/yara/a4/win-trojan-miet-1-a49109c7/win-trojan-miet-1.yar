rule Win_Trojan_Miet_1
{
strings:
	$a0 = { 4064f3c3b91e00ba3d002e8e1e7fc39102e8eaffb80300c6f277e500ffff04c0558bec833e4c01 }


condition:
	$a0
}