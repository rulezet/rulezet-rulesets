rule Win_Trojan_SeventhSon_2
{
strings:
	$a0 = { ed0301be8b0103f5bf0001a5a5b80033cd21 }


condition:
	$a0
}