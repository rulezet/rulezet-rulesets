rule Win_Trojan_Sumo_3
{
strings:
	$a0 = { 73756d6f2e7368 }

	$a1 = { 2470617373203e202f746d702f706173732e6c6f67 }


condition:
	$a0 and $a1
}