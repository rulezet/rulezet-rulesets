rule Win_Trojan_Abbas_2
{
strings:
	$a0 = { 86008ec126817f034b55743b2e898d0c002e899d0a }


condition:
	$a0
}