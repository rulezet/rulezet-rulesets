rule Win_Trojan_Mmir_2
{
strings:
	$a0 = { 450ec74510c0ffb440b90c01ba4002cd21b8004233c999cd21b4408bd759cd21b43ecd2107 }


condition:
	$a0
}