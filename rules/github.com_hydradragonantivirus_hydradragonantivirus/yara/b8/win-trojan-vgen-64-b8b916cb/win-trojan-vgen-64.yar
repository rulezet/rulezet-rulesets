rule Win_Trojan_VGEN_64
{
strings:
	$a0 = { bc007c0e070e1fbe237dbf0003b93800f3a4be4c0066a5066800f00733db4326813fcd1875f8be4c00891c8c4402 }


condition:
	$a0
}