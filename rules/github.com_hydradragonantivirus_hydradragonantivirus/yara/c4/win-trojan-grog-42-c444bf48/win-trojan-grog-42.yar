rule Win_Trojan_Grog_42
{
strings:
	$a0 = { b8003dcd218bd8b903008d954502b43fcd21b80242995259 }


condition:
	$a0
}