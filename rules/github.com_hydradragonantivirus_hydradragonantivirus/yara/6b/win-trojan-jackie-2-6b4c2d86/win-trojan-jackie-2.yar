rule Win_Trojan_Jackie_2
{
strings:
	$a0 = { 6965325d202e2e209a000071005589e5b800029acd02710081ec0002c606501801c60656 }


condition:
	$a0
}