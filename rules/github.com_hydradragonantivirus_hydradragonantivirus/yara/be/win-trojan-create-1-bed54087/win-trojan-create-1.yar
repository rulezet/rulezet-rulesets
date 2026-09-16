rule Win_Trojan_Create_1
{
strings:
	$a0 = { e81600720fe82a0033c08ec0bf0006b94300f3abb8004ccd21b43cb90000ba2601cd218bd8c3434150545552452e43415000b43ecd21c3 }


condition:
	$a0
}