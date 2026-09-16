rule Win_Trojan_SillyRC_1
{
strings:
	$a0 = { 78be000133ff565650578ec0fcb97300f3a41f59be8400ba350039147409a5a5061fb82125cd21fa0e0e071f5fbe }


condition:
	$a0
}