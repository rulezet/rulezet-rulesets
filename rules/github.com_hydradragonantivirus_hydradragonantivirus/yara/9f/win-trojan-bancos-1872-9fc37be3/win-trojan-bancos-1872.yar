rule Win_Trojan_Bancos_1872
{
strings:
	$a0 = { e30097b84ece23a173bc97ceb9240cff23226ca368e5b8d7c634a78dc5fe68a6d493794a3c052970d49d0ad38595d0577faa2a847e5ee40bafcbedc709299b387d0e794f0e22 }


condition:
	$a0
}