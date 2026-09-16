rule Win_Trojan_AJ_1
{
strings:
	$a0 = { 01414a8306700129b800429933c9cd21b440b92000ba6601cd21b402b207cd21b43ecd211f }


condition:
	$a0
}