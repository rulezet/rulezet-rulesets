rule Win_Trojan_Bancos_1787
{
strings:
	$a0 = { 8a5445bcfcc059f09a2f4a272c1b489b15dbbdc61d5f1012fe35a52e5044ac532c943929cd8ea5a0c4a1a1a33a13f7d267f04f271558d131bdf3a84c4fb5940cae35c4b74d21 }


condition:
	$a0
}