rule Win_Trojan_JAVA_2
{
strings:
	$a0 = { 2ab700012a100bbc08b500022a110c2fbc08b500032a1101b4bc08b500042ab40002100a03542ab4 }


condition:
	$a0
}