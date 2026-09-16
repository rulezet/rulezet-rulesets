rule Win_Trojan_Simple_5
{
strings:
	$a0 = { cd218bd8b440ba00012e8b0e0301cd21b43ecd2172 }


condition:
	$a0
}