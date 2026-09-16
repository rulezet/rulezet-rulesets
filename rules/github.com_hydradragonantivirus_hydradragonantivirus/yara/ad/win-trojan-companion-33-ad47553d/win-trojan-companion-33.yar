rule Win_Trojan_Companion_33
{
strings:
	$a0 = { 26c705434f4d00b4565fcd217217b43cb102cd210e1f93b440b95f00ba0001cd21b43ecd211f07 }


condition:
	$a0
}