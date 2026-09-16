rule Win_Trojan_Tiny_26
{
strings:
	$a0 = { 5901960e59f3a4ba5301b44ecd217301cbb8023d99b29ecd2193b43fba59015459cd215087d6ac }


condition:
	$a0
}