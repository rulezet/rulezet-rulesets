rule Win_Trojan_BA_3
{
strings:
	$a0 = { 42417441bb80008b571a81c2b50081c20001891606 }


condition:
	$a0
}