rule Win_Trojan_Rycol_1
{
strings:
	$a0 = { 8b45f83b45ec7c08eb5e8db6000000006a108b45f4506a006a268d45c4508b45fc50e891fcffff83c41889c083f8ff751768db8a0408e83dfcffff83c4046a01e8d3fcffff }

	$a1 = { 797468656d20436f6c6c }


condition:
	$a0 and $a1
}