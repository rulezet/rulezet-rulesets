rule Win_Trojan_Delf_408
{
strings:
	$a0 = { ba10c449008bc3e8b5faffffba28c449008bc3e8a9faffffba3cc449008bc3e89dfaffffba58c449008bc3e891faffff }


condition:
	$a0
}