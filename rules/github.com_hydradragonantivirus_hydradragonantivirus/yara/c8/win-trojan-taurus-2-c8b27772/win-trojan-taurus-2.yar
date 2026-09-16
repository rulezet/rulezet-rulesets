rule Win_Trojan_Taurus_2
{
strings:
	$a0 = { 8905b440b90300ba5a0203d6cd21b8024233d233c9 }


condition:
	$a0
}