rule Win_Trojan_Pipi_1
{
strings:
	$a0 = { 7502b4ee3d004b743780fced750af3a4585858b800 }


condition:
	$a0
}