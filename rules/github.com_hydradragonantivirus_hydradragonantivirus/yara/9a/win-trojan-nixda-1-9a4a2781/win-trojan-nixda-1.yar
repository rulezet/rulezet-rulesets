rule Win_Trojan_Nixda_1
{
strings:
	$a0 = { 86f4fd01048b86f4fd31d20386f8fd1396fafd83fa007f077c163de0227611b8e02231d22b86f8 }


condition:
	$a0
}