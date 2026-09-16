rule Win_Trojan_Vgen_18
{
strings:
	$a0 = { 15337572f9d4ff8ac4b40bbb0dd0cd210bdb74661e8cd8488ed82bff803d5a7559836d0327836d12278e4512e8 }


condition:
	$a0
}