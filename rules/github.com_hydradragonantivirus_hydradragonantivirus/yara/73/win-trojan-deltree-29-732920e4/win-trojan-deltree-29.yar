rule Win_Trojan_Deltree_29
{
strings:
	$a0 = { 64656c20633a5c696f2e737973[0-52]64656c74726565202f7920633a5c77696e646f7773 }


condition:
	$a0
}