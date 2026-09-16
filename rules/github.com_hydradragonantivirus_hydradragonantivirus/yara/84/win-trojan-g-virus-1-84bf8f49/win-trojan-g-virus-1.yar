rule Win_Trojan_G_Virus_1
{
strings:
	$a0 = { 83ef03e800005e81ee87002e89845900 }


condition:
	$a0
}