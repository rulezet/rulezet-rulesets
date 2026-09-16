rule Win_Trojan_LittlePieces_2
{
strings:
	$a0 = { ca020033db8edbc7474c56018c4f4e }


condition:
	$a0
}