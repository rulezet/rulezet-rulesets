rule Win_Trojan_VisME_1
{
strings:
	$a0 = { 8000b41acd21bf0001bea20703f5578bc42d060050b8cf0050b8f3a4508bcc2bcefa83c404c3 }


condition:
	$a0
}