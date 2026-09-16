rule Win_Trojan_Mmir_1
{
strings:
	$a0 = { 0ec74510c0ffb440b9ee00ba4002cd21b8004233c999cd21b4408bd759cd21b43ecd21071f61 }


condition:
	$a0
}