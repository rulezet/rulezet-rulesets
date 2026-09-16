rule Win_Trojan_Remor_6
{
strings:
	$a0 = { 02a3fd02a1ff02a322038a2632038b16fd020316220381c22001cd2183c21e891624038b }


condition:
	$a0
}