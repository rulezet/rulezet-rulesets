rule Win_Trojan_L_28
{
strings:
	$a0 = { 0204c606b70200b92700ba1501b44ecd213d12007403e82200b92700ba1b01b44ecd213d12 }


condition:
	$a0
}