rule Win_Trojan_Lame_4
{
strings:
	$a0 = { b440b90300ba0001cd21b8024233c933d2cd21b440b9cf008d960501cd21fe86b301b43ecd21 }


condition:
	$a0
}