rule Win_Trojan_BOO_13
{
strings:
	$a0 = { 7c0e1fff0e1304cd12b10ad3c88ec033ff8bf4b90001f3a506b8630050cb2ec606e80100ff36 }


condition:
	$a0
}