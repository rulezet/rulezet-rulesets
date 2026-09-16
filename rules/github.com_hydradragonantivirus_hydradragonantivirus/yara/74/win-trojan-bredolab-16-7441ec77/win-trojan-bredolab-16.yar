rule Win_Trojan_Bredolab_16
{
strings:
	$a0 = { 558bec8bf933cb4e4b462bf8474b43 }


condition:
	$a0
}