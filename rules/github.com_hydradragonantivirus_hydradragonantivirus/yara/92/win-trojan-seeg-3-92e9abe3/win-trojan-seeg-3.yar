rule Win_Trojan_Seeg_3
{
strings:
	$a0 = { 52371785a01045cea8c33f6bc89c86690fe955552817177413f07707c0278e41c007a206f3ba9507 }


condition:
	$a0
}