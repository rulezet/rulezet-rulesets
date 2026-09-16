rule Win_Trojan_HH_4
{
strings:
	$a0 = { cd21b440b912018d960601cd21b43ecd21 }


condition:
	$a0
}