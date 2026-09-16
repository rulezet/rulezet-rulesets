rule Win_Trojan_Seagull_1
{
strings:
	$a0 = { cd21b8004233c933d2cd21b440ba0001b9c001cd21b440bac0028b0ea802cd21b43ecd21ff36ae02 }


condition:
	$a0
}