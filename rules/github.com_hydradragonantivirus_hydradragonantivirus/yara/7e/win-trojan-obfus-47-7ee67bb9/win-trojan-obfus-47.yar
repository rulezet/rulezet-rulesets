rule Win_Trojan_Obfus_47
{
strings:
	$a0 = { c7842458feffffad3e5399c7842474fdffffad3e5399b902000000c18c2458feff }


condition:
	$a0
}