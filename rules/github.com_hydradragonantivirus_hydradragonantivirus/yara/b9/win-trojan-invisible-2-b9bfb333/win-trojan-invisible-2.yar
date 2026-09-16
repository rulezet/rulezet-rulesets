rule Win_Trojan_Invisible_2
{
strings:
	$a0 = { 5b1fbb38627900b9a12f2c00ba916481c1a6dc740077003097c89f7c007e004300f2535be2f1 }


condition:
	$a0
}