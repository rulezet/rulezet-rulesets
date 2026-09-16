rule Win_Trojan_Ruts_1
{
strings:
	$a0 = { ff56b899020e50be9402bfe112b905000657f3a48bd1b9920dcbb440cd21cb5ee8aaffc3 }


condition:
	$a0
}