rule Win_Trojan_Emhaka_3
{
strings:
	$a0 = { ee03b8ffffcd213d000074040ee837002e81bca2024d5a }


condition:
	$a0
}