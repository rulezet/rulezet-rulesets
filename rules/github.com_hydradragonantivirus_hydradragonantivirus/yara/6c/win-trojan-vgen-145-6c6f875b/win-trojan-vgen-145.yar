rule Win_Trojan_Vgen_145
{
strings:
	$a0 = { ff0080120023006c6170696464616e56e800005e2e899cb0012e8c84b2015ecb1e06600e1fe800005d2ec49e9b }


condition:
	$a0
}