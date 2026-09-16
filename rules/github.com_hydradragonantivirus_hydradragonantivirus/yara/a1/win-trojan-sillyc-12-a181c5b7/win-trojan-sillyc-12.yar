rule Win_Trojan_SillyC_12
{
strings:
	$a0 = { cd21b440b255b103cd2161b002cd21b440b1678bd6cd21b43ecd21b44fcd2173bec32a2e434f }


condition:
	$a0
}