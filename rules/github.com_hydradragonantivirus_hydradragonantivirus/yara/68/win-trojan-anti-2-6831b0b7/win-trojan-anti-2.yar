rule Win_Trojan_Anti_2
{
strings:
	$a0 = { e86700beb003e853028b4cfe83e10383c1038344fe0451e8cf00593c007502e2f5e81200817cfe00037603e81600e8 }


condition:
	$a0
}