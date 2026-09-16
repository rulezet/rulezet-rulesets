rule Win_Trojan_REM_1
{
strings:
	$a0 = { 0c011e01051560050d03ffff3d21 }


condition:
	$a0
}