rule Win_Trojan_LAPID457_1
{
strings:
	$a0 = { 96cd01cd21b8024233c933d2cd21b440b912008d96de01cd21b440b9b7018d961200cd21b80157 }


condition:
	$a0
}