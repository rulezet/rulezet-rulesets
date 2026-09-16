rule Win_Trojan_Enigma_2
{
strings:
	$a0 = { 058cd80e1fbef20681ee030103f38904bef40681ee030103f38cc089040e0753b8002fcd218bcb5bbe0b0b81ee030103f3890c83c6028cc089040e07bf8f }


condition:
	$a0
}