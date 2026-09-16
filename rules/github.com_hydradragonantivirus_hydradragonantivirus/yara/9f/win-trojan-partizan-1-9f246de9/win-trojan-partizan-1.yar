rule Win_Trojan_Partizan_1
{
strings:
	$a0 = { f54d5a7429b8024233c933d2cd21a3ff01b440b90701ba00f5cd21b8004233c933d2cd21b4 }


condition:
	$a0
}