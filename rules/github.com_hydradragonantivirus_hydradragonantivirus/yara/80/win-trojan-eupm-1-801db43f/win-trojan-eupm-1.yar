rule Win_Trojan_Eupm_1
{
strings:
	$a0 = { bf03002ea000002e000547e2fae9c3fc }


condition:
	$a0
}