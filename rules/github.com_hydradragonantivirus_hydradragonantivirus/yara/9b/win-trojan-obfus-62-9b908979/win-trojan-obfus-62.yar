rule Win_Trojan_Obfus_62
{
strings:
	$a0 = { 51b067412bcf2b0526c74000290d9da44000b13c6bc81603c88bcc2bc8290d92 }


condition:
	$a0
}