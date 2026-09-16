rule Win_Trojan_Trojan_148
{
strings:
	$a0 = { ba0001cd217203eb01908f0605018f060301b43ecd }


condition:
	$a0
}