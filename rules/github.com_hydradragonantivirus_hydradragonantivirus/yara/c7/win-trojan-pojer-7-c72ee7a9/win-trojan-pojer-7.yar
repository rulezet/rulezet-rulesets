rule Win_Trojan_Pojer_7
{
strings:
	$a0 = { b8d551401341adef256769d3b1a292aa5f5c1da2a28a2b9d }


condition:
	$a0
}