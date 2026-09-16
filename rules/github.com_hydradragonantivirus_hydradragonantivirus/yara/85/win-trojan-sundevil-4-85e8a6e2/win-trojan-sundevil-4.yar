rule Win_Trojan_Sundevil_4
{
strings:
	$a0 = { 028ec033ff8bf5b9fa03f3a433c08ed8b8fd01a384 }


condition:
	$a0
}