rule Win_Trojan_Banker_6346
{
strings:
	$a0 = { 60e8000000008b2c2483c404837c242801750c8b4424248985f30c0000eb0c8b }


condition:
	$a0
}