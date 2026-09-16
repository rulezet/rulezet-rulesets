rule Win_Trojan_Click_3
{
strings:
	$a0 = { f0b800428b1e730233c9ba770190cd217233b87701a37502b440ba77028bce8b1e7302cd21721e }


condition:
	$a0
}