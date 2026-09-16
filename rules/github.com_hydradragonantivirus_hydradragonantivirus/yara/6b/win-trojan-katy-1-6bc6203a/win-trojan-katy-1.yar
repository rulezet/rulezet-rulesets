rule Win_Trojan_Katy_1
{
strings:
	$a0 = { 8dbe450033d2b81218cd212e3286320086e0e80b00eb13 }


condition:
	$a0
}