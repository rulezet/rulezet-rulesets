rule Win_Trojan_Trojan_244
{
strings:
	$a0 = { 03002e8986870232c0e8ab00b440b903008d968602cd21b002e89b00b440b984018d960301cd21 }


condition:
	$a0
}