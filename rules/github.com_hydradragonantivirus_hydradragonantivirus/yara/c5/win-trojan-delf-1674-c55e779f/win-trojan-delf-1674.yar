rule Win_Trojan_Delf_1674
{
strings:
	$a0 = { 558bec83c4ec53565733c08945ecb8b08f4100e894ccfeff33c05568c99041[0-121]374539383837423234 }


condition:
	$a0
}