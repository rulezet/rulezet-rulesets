rule Win_Trojan_Philis_107
{
strings:
	$a0 = { 909060566816f700005e5ee800000000 }


condition:
	$a0
}