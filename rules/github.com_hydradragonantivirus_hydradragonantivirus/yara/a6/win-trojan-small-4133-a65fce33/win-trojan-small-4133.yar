rule Win_Trojan_Small_4133
{
strings:
	$a0 = { e815000000be800032??c1c60fe81d00000039ef75ef891c24 }


condition:
	$a0
}