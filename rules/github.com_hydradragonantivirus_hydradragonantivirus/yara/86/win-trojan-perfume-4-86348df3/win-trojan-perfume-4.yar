rule Win_Trojan_Perfume_4
{
strings:
	$a0 = { 030040b82135cd212e891e61002e }


condition:
	$a0
}