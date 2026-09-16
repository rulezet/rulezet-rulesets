rule Win_Trojan_Lineage_107
{
strings:
	$a0 = { e22400afa70920dbe07b6fbc484e27a0d5a3f58bc622003f528dde449d87a7209dd11ed2fbd9c3ac8a0a5de0e3cd53fd2b5ef2b165832cddab3c761fd60fdc804c0c0611 }


condition:
	$a0
}