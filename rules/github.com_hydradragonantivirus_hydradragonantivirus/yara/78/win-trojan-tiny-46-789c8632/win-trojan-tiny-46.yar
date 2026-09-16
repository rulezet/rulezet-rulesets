rule Win_Trojan_Tiny_46
{
strings:
	$a0 = { 3dcd218bd8e83a00b43fb1040e1fba9e00cd21803e9e004d7416b002e82500a30200b9a200 }


condition:
	$a0
}