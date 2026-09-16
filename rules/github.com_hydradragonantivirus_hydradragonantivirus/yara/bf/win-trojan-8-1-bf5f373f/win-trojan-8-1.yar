rule Win_Trojan_8_1
{
strings:
	$a0 = { 445b7219b8907ee8c800b80835cd21895c5d }


condition:
	$a0
}