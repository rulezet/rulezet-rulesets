rule Win_Trojan_SillyC_9
{
strings:
	$a0 = { 8cd880c4108ec0b165f3a4b44eba5f01b120cd21b39ad02f7216b44fcd2173f606ba2a0052cb1616071f5fb5 }


condition:
	$a0
}