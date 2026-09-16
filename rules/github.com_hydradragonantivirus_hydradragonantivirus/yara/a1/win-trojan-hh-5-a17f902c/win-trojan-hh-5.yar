rule Win_Trojan_HH_5
{
strings:
	$a0 = { cd21b440b916018d960601cd21b43ecd21 }


condition:
	$a0
}