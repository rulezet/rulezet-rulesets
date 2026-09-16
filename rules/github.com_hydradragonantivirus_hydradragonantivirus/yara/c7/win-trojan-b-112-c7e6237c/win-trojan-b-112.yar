rule Win_Trojan_B_112
{
strings:
	$a0 = { db8edb8ed3be007c8be6fb832e130401cd120e1fb106d3e0508ec033ffb90001f3a5b86b0050cb }


condition:
	$a0
}