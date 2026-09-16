rule Win_Trojan_Anti_3
{
strings:
	$a0 = { 6700beb703e853028b4cfe83e10383c1038344fe0451e8cf00593c007502e2f5e81200817cfe00037603e81600e8 }


condition:
	$a0
}