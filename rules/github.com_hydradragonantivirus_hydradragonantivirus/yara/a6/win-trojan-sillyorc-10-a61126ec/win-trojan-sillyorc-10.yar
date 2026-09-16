rule Win_Trojan_SillyORC_10
{
strings:
	$a0 = { 0200ba3c010e1fcd21a13c013d4d5a7413b8004233d233c9cd21b440b9b100ba0001cd21b8003e }


condition:
	$a0
}