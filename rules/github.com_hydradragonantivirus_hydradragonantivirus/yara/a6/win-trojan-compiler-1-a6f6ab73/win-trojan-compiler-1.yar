rule Win_Trojan_Compiler_1
{
strings:
	$a0 = { 03008944ec8954eab440b9000431d2e8d800e88400b440b92000ba5c02e8ca00e947ff8cc383c3 }


condition:
	$a0
}