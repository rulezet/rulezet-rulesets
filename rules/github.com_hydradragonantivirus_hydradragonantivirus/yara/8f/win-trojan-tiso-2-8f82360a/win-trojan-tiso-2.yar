rule Win_Trojan_Tiso_2
{
strings:
	$a0 = { e800005d8d760fb93b038a46fc300446e2fb }


condition:
	$a0
}