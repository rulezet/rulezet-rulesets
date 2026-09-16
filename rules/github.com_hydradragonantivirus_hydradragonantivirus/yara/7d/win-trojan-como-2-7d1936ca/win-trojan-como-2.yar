rule Win_Trojan_Como_2
{
strings:
	$a0 = { 8cca8ed2bc8e0081c4800050531e06e81f00e80307 }


condition:
	$a0
}