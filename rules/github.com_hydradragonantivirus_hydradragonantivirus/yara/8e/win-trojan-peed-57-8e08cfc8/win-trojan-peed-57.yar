rule Win_Trojan_Peed_57
{
strings:
	$a0 = { 6a006a014889c583ed0283ed036609edf27405050002000089ea09eaf275e8bf419b409a01 }


condition:
	$a0
}