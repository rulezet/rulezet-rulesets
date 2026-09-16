rule Win_Trojan_DoomMbr_1
{
strings:
	$a0 = { ed072e807e00e974108cc00510002e034602502eff7600eb088bfe8bf50e57a5a5b280e85500cb444f4f4dfcfa33 }


condition:
	$a0
}