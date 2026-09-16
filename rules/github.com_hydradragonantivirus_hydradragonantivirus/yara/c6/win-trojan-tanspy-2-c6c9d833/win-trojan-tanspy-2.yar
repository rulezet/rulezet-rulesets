rule Win_Trojan_Tanspy_2
{
strings:
	$a0 = { 68201540008d4dece89d0300008d45ec8bcf50c645fc03e822e0ffff }


condition:
	$a0
}