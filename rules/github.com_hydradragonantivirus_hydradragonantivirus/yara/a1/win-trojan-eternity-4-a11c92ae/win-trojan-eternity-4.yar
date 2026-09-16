rule Win_Trojan_Eternity_4
{
strings:
	$a0 = { 01faba4559cd16e800005d83ed0ce81400eb24e80f00b440b957028bd5cd21e80300c3 }


condition:
	$a0
}