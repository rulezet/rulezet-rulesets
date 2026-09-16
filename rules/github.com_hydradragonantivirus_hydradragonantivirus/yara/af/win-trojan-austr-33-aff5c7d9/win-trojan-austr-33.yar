rule Win_Trojan_Austr_33
{
strings:
	$a0 = { 33c9cd218bd8b440b9070e8d963102cd21b43ecd21c3 }


condition:
	$a0
}