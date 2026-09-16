rule Win_Trojan_G_6
{
strings:
	$a0 = { 1000b958012e8107000083c302e2f68beccc8b6efa81ed13001e06b8424bcd213d534674428cd8488ed8812e030080 }


condition:
	$a0
}