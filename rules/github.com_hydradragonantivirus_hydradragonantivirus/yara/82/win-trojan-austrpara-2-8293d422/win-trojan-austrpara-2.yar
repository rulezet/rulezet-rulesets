rule Win_Trojan_AustrPara_2
{
strings:
	$a0 = { 01b440b199b601cd21b8004233d233c9cd21b440b601b104cd21b43ecd21 }


condition:
	$a0
}