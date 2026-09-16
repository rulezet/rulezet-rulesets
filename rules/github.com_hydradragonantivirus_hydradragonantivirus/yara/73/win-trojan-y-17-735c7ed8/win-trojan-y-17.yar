rule Win_Trojan_Y_17
{
strings:
	$a0 = { 120446ff0cadc1e0068ec0bb007c89dee81b00be4c00a5a5c744fca3008944fe06b86b0050cb8e }


condition:
	$a0
}