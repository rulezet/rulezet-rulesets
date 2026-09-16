rule Win_Trojan_Lamerman_1
{
strings:
	$a0 = { 8bde8be6fbff0e1304cd12b90602d3e08ec0b827000650f3a4cbc43e4c0060b404cd1a80fa }


condition:
	$a0
}