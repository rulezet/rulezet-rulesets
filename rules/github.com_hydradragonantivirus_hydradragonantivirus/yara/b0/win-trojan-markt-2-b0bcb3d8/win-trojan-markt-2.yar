rule Win_Trojan_Markt_2
{
strings:
	$a0 = { 01faba4559cd16b8050333dbcd16b801faba4559cd21e800005d555d81ed1f01c6862a01 }


condition:
	$a0
}