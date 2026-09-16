rule Win_Trojan_SCAP_1
{
strings:
	$a0 = { 0473022bc0894606b80142b9ffffbaf8ffcd21b4408bd5b90800cd218bbe3202578bd7e82900 }


condition:
	$a0
}