rule Win_Trojan_Ducktoy_1
{
strings:
	$a0 = { 4475636b746f7920312e302e31000000ffffffff0200000020200000ffffffff1600000043726561 }


condition:
	$a0
}