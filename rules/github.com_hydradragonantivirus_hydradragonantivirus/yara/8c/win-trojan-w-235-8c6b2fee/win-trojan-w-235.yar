rule Win_Trojan_W_235
{
strings:
	$a0 = { b961060000b300ac32c3aae2fae98af9ffff00000000 }


condition:
	$a0
}