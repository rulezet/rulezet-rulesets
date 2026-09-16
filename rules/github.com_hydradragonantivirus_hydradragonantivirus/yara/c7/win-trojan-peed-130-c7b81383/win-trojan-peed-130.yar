rule Win_Trojan_Peed_130
{
strings:
	$a0 = { 5259f7d0eb0c5589e5ad83ee0546c9c20800e80?000000 }


condition:
	$a0
}