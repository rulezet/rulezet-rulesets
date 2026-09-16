rule Win_Trojan_Greenie_1
{
strings:
	$a0 = { 0300f3a487deb430bf5349cd2181ff4559746f0e8cc8488ec026803e00005a7515b83a00 }


condition:
	$a0
}